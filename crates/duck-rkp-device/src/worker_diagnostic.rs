use std::{io::Read as _, io::Write as _};

use serde_json::json;

use super::*;

fn bounded_text(path: &Path) -> serde_json::Value {
    let result = fs::File::open(path).and_then(|file| {
        let mut text = String::new();
        file.take(131072).read_to_string(&mut text)?;
        Ok(text)
    });
    match result {
        Ok(text) => json!({"text": text, "limit_bytes": 131072}),
        Err(error) => json!({"error": error.to_string()}),
    }
}

fn cbor_shape(value: &ciborium::value::Value, depth: usize) -> serde_json::Value {
    use ciborium::value::Value;

    if depth > 16 {
        return json!({"truncated": true});
    }
    match value {
        Value::Bytes(bytes) => {
            json!({"type": "bytes", "length": bytes.len(), "value": "redacted"})
        }
        Value::Integer(number) => {
            json!({"type": "integer", "value": format!("{number:?}")})
        }
        Value::Array(items) => {
            let values: Vec<_> = items
                .iter()
                .take(64)
                .map(|item| cbor_shape(item, depth + 1))
                .collect();
            json!({"type": "array", "length": items.len(), "items": values})
        }
        Value::Map(items) => {
            let entries: Vec<_> = items
                .iter()
                .take(64)
                .map(|(key, value)| {
                    json!({
                        "key": cbor_shape(key, depth + 1),
                        "value": cbor_shape(value, depth + 1)
                    })
                })
                .collect();
            json!({"type": "map", "length": items.len(), "entries": entries})
        }
        _ => json!({"type": "other", "value": "redacted"}),
    }
}

pub(super) fn write(
    exchange: &Path,
    paths: &AppPaths,
    request: &[u8],
    result: &Result<Vec<u8>>,
    elapsed: Duration,
) -> Result<()> {
    let command = request
        .get(..4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()));
    let decoded = request.get(4..).map(protocol::decode_exact);
    let request_shape = match &decoded {
        Some(Ok(value)) => cbor_shape(value, 0),
        Some(Err(error)) => json!({"error": format!("{error:#}")}),
        None => json!({"error": "missing command"}),
    };
    let mut embedded = json!(null);
    if let Some(Ok(ciborium::value::Value::Map(fields))) = &decoded {
        let label = if command == Some(0x311e) { 58 } else { 57 };
        for (key, value) in fields {
            if key == &ciborium::value::Value::Integer(label.into())
                && let ciborium::value::Value::Bytes(bytes) = value
            {
                embedded = match protocol::decode_exact(bytes) {
                    Ok(value) => cbor_shape(&value, 0),
                    Err(error) => json!({"error": format!("{error:#}")}),
                };
            }
        }
    }
    let response = match read_exchange_file(&exchange.join("response.bin"), BUFFER_SIZE) {
        Ok(bytes) => {
            let status = bytes
                .get(..4)
                .map(|part| i32::from_le_bytes(part.try_into().unwrap()));
            let length = bytes
                .get(4..8)
                .map(|part| u32::from_le_bytes(part.try_into().unwrap()));
            let prefix = bytes
                .iter()
                .take(64)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let nonzero = bytes.iter().skip(8).filter(|byte| **byte != 0).count();
            json!({
                "length": bytes.len(),
                "status": status,
                "length_word_uninterpreted": length,
                "prefix_hex": prefix,
                "nonzero_after_header": nonzero
            })
        }
        Err(error) => json!({"error": format!("{error:#}")}),
    };
    let mut properties = serde_json::Map::new();
    #[cfg(target_os = "android")]
    for key in [
        "ro.build.fingerprint",
        "ro.vendor.build.fingerprint",
        "ro.build.version.sdk",
        "ro.vendor.build.security_patch",
        "ro.product.device",
        "ro.soc.manufacturer",
        "ro.soc.model",
        "ro.boot.verifiedbootstate",
    ] {
        let value = match Command::new("/system/bin/getprop").arg(key).output() {
            Ok(output) => {
                let text: String = String::from_utf8_lossy(&output.stdout)
                    .chars()
                    .take(4096)
                    .collect();
                json!({"success": output.status.success(), "value": text.trim()})
            }
            Err(error) => json!({"error": error.to_string()}),
        };
        properties.insert(key.into(), value);
    }
    properties.insert("kernel".into(), bounded_text(Path::new("/proc/version")));
    properties.insert("module".into(), bounded_text(&paths.root.join("module.prop")));
    let validation_error = protocol::ta_payload(request)
        .err()
        .map(|error| format!("{error:#}"));
    let worker_error = result.as_ref().err().map(|error| format!("{error:#}"));
    let report = json!({
        "schema_version": 1,
        "scope": "one native TA attempt; not HTTP, AIDL or full provisioning",
        "package_version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "elapsed_ms": elapsed.as_millis() as u64,
        "timeout_seconds": TIMEOUT.as_secs(),
        "command": command.map(|value| format!("0x{value:04x}")),
        "request_length": request.len(),
        "request_shape": request_shape,
        "embedded_cbor_shape": embedded,
        "local_validation_error": validation_error,
        "response": response,
        "worker_success": result.is_ok(),
        "worker_error": worker_error,
        "environment": properties,
        "vendor_library_path": VENDOR_LIBRARY_PATH,
        "limitations": [
            "No cryptographic MAC or signature verification",
            "Vendor ABI and status semantics are not proven",
            "Request byte values redacted; raw local dumps can contain secrets",
            "Firmware fingerprints and response prefix may identify the device; review before sharing"
        ]
    });
    let content = serde_json::to_vec_pretty(&report)?;
    let directory = paths.tmp_dir.join("rkp-device-reports");
    fs::create_dir_all(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let mut file = tempfile::NamedTempFile::new_in(&directory)?;
    file.write_all(&content)?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let name = format!(
        "rkp-{:04x}-{stamp}-{}.json",
        command.unwrap_or(0),
        std::process::id()
    );
    let report_path = directory.join(name);
    file.persist_noclobber(&report_path)
        .map_err(|error| error.error)?;
    fs::write(exchange.join("report.json"), &content)?;
    fs::set_permissions(
        exchange.join("report.json"),
        fs::Permissions::from_mode(0o600),
    )?;
    eprintln!("RKP diagnostic report: {}", report_path.display());
    Ok(())
}

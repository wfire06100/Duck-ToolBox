use std::{fs, io::Read as _, os::unix::fs::PermissionsExt as _, path::Path, process::Command, time::Duration};
use anyhow::{Context, Result};
use duck_core::AppPaths;
use serde::{Deserialize, Serialize};
use crate::{error::DeviceRkpError, process::{self, read_exchange_file}, protocol::{self, BUFFER_SIZE, MAX_REQUEST_SIZE}};
const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REPLY_FILE: usize = BUFFER_SIZE * 6;
const VENDOR_LIBRARY_PATH: &str = "/system/lib64:/vendor/lib64:/odm/lib64:/vendor/lib64/hw:/odm/lib64/hw";
#[derive(Serialize, Deserialize)]
enum Reply { Payload(Vec<u8>), Error(DeviceRkpError) }
impl Reply {
    fn from_result(result: Result<Vec<u8>>) -> Self {
        match result { Ok(payload) => Self::Payload(payload), Err(error) => Self::Error(error.downcast::<DeviceRkpError>().unwrap_or_else(|error| DeviceRkpError::Transport(format!("{error:#}")))) }
    }
    fn into_result(self) -> Result<Vec<u8>> {
        match self { Self::Payload(payload) if payload.len() <= BUFFER_SIZE => Ok(payload), Self::Payload(_) => Err(DeviceRkpError::InvalidResponse("payload too large".into()).into()), Self::Error(error) => Err(error.into()) }
    }
}
pub(crate) fn sign(paths: &AppPaths, request: &[u8]) -> Result<Vec<u8>> {
    let local = |error: anyhow::Error| -> anyhow::Error { if error.is::<DeviceRkpError>() { error } else { DeviceRkpError::Transport(format!("device RKP worker failed: {error:#}")).into() } };
    fs::create_dir_all(&paths.tmp_dir).with_context(|| format!("create {}", paths.tmp_dir.display())).map_err(local)?;
    let exchange = tempfile::Builder::new().prefix("rkp-device-").permissions(fs::Permissions::from_mode(0o700)).tempdir_in(&paths.tmp_dir)?;
    fs::write(exchange.path().join("request.bin"), request).context("write the worker request").map_err(local)?;
    let started = std::time::Instant::now();
    let result = (|| -> Result<Vec<u8>> {
        let executable = std::env::current_exe().context("locate this executable").map_err(local)?;
        let mut command = Command::new(&executable);
        command.env("LD_LIBRARY_PATH", VENDOR_LIBRARY_PATH).args(["rkp-device", "ta-csr", "--exchange"]).arg(exchange.path());
        let status = process::run(&mut command, TIMEOUT)?;
        let reply_path = exchange.path().join("reply.json");
        if !status.success() || !reply_path.is_file() { return Err(DeviceRkpError::Transport(format!("worker exited with {status}; vendor ABI may be incompatible")).into()); }
        let reply = read_exchange_file(&reply_path, MAX_REPLY_FILE).map_err(local)?;
        serde_json::from_slice::<Reply>(&reply).context("parse the worker reply").map_err(|error| DeviceRkpError::InvalidResponse(format!("{error:#}")))?.into_result()
    })();
    if let Err(error) = diagnostic(exchange.path(), paths, request, &result, started.elapsed()) { eprintln!("RKP diagnostic unavailable: {error:#}"); }
    preserve_exchange(exchange.path(), &paths.tmp_dir);
    result
}
fn bounded_text(path: &Path) -> serde_json::Value {
    match fs::File::open(path).and_then(|file| { let mut text = String::new(); file.take(131072).read_to_string(&mut text)?; Ok(text) }) {
        Ok(text) => serde_json::json!({"text": text, "limit_bytes": 131072}),
        Err(error) => serde_json::json!({"error": error.to_string()})
    }
}
fn cbor_shape(value: &ciborium::value::Value, depth: usize) -> serde_json::Value {
    use ciborium::value::Value;
    use serde_json::json;
    if depth > 16 { return json!({"truncated": true}); }
    match value {
        Value::Bytes(bytes) => json!({"type": "bytes", "length": bytes.len(), "value": "redacted"}),
        Value::Integer(number) => json!({"type": "integer", "value": format!("{number:?}")}),
        Value::Array(items) => json!({"type": "array", "length": items.len(), "items": items.iter().take(64).map(|item| cbor_shape(item, depth + 1)).collect::<Vec<_>>()}),
        Value::Map(items) => json!({"type": "map", "length": items.len(), "entries": items.iter().take(64).map(|(key, value)| json!({"key": cbor_shape(key, depth + 1), "value": cbor_shape(value, depth + 1)})).collect::<Vec<_>>()}),
        _ => json!({"type": "other", "value": "redacted"})
    }
}
fn diagnostic(exchange: &Path, paths: &AppPaths, request: &[u8], result: &Result<Vec<u8>>, elapsed: Duration) -> Result<()> {
    use serde_json::json;
    let command = request.get(..4).map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()));
    let decoded = request.get(4..).map(protocol::decode_exact);
    let request_shape = match &decoded { Some(Ok(value)) => cbor_shape(value, 0), Some(Err(error)) => json!({"error": format!("{error:#}")}), None => json!({"error": "missing command"}) };
    let mut embedded = json!(null);
    if let Some(Ok(ciborium::value::Value::Map(fields))) = &decoded {
        let label = if command == Some(0x311e) { 58 } else { 57 };
        for (key, value) in fields {
            if key == &ciborium::value::Value::Integer(label.into()) {
                if let ciborium::value::Value::Bytes(bytes) = value {
                    embedded = match protocol::decode_exact(bytes) { Ok(value) => cbor_shape(&value, 0), Err(error) => json!({"error": format!("{error:#}")}) };
                }
            }
        }
    }
    let response = match read_exchange_file(&exchange.join("response.bin"), BUFFER_SIZE) {
        Ok(bytes) => json!({"length": bytes.len(), "status": bytes.get(..4).map(|part| i32::from_le_bytes(part.try_into().unwrap())), "length_word_uninterpreted": bytes.get(4..8).map(|part| u32::from_le_bytes(part.try_into().unwrap())), "prefix_hex": bytes.iter().take(64).map(|byte| format!("{byte:02x}")).collect::<String>(), "nonzero_after_header": bytes.iter().skip(8).filter(|byte| **byte != 0).count()}),
        Err(error) => json!({"error": format!("{error:#}")})
    };
    let mut properties = serde_json::Map::new();
    #[cfg(target_os = "android")]
    for key in ["ro.build.fingerprint", "ro.vendor.build.fingerprint", "ro.build.version.sdk", "ro.vendor.build.security_patch", "ro.product.device", "ro.soc.manufacturer", "ro.soc.model", "ro.boot.verifiedbootstate"] {
        let value = Command::new("/system/bin/getprop").arg(key).output();
        properties.insert(key.into(), match value { Ok(output) => json!({"success": output.status.success(), "value": String::from_utf8_lossy(&output.stdout).chars().take(4096).collect::<String>().trim()}), Err(error) => json!({"error": error.to_string()}) });
    }
    properties.insert("kernel".into(), bounded_text(Path::new("/proc/version")));
    properties.insert("module".into(), bounded_text(&paths.root.join("module.prop")));
    let report = json!({"schema_version": 1, "scope": "one native TA attempt; not HTTP, AIDL or full provisioning", "package_version": env!("CARGO_PKG_VERSION"), "os": std::env::consts::OS, "arch": std::env::consts::ARCH, "elapsed_ms": elapsed.as_millis() as u64, "timeout_seconds": TIMEOUT.as_secs(), "command": command.map(|value| format!("0x{value:04x}")), "request_length": request.len(), "request_shape": request_shape, "embedded_cbor_shape": embedded, "local_validation_error": protocol::ta_payload(request).err().map(|error| format!("{error:#}")), "response": response, "worker_success": result.is_ok(), "worker_error": result.as_ref().err().map(|error| format!("{error:#}")), "environment": properties, "vendor_library_path": VENDOR_LIBRARY_PATH, "limitations": ["No cryptographic MAC or signature verification", "Vendor ABI and status semantics are not proven", "Request byte values redacted; raw local dumps can contain secrets", "Firmware fingerprints and response prefix may identify the device; review before sharing"]});
    let content = serde_json::to_vec_pretty(&report)?;
    let directory = paths.tmp_dir.join("rkp-device-reports");
    fs::create_dir_all(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let mut file = tempfile::NamedTempFile::new_in(&directory)?;
    use std::io::Write as _;
    file.write_all(&content)?;
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let name = format!("rkp-{:04x}-{stamp}-{}.json", command.unwrap_or(0), std::process::id());
    let report_path = directory.join(name);
    file.persist_noclobber(&report_path).map_err(|error| error.error)?;
    fs::write(exchange.join("report.json"), &content)?;
    fs::set_permissions(exchange.join("report.json"), fs::Permissions::from_mode(0o600))?;
    eprintln!("RKP diagnostic report: {}", report_path.display());
    Ok(())
}
fn preserve_exchange(exchange: &Path, tmp_dir: &Path) {
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|duration| duration.as_millis()).unwrap_or_default();
    let destination = tmp_dir.join("rkp-device-debug").join(format!("rkp-device-{stamp}"));
    if fs::create_dir_all(&destination).is_err() { return; }
    for name in ["request.bin", "response.bin", "reply.json", "report.json"] {
        let source = exchange.join(name);
        if source.is_file() { let _ = fs::copy(&source, destination.join(name)); }
    }
}
pub(crate) fn execute(exchange: &Path) -> Result<()> {
    let result = (|| { let request = read_exchange_file(&exchange.join("request.bin"), MAX_REQUEST_SIZE)?; protocol::ta_payload(&request)?; native_request(&request, Some(exchange)) })();
    let reply = Reply::from_result(result);
    let encoded = serde_json::to_vec(&reply).context("encode the worker reply")?;
    fs::write(exchange.join("reply.json"), encoded).context("write the worker reply").map_err(|error| DeviceRkpError::InvalidResponse(format!("{error:#}")))?;
    Ok(())
}
pub(crate) fn dump_hex(exchange: &Path) -> Result<()> {
    for name in ["request.bin", "response.bin"] {
        let source = exchange.join(name);
        let bytes = fs::read(&source).with_context(|| format!("read {}", source.display()))?;
        let hex = bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let destination = exchange.join(name.replace(".bin", ".hex"));
        fs::write(&destination, hex).with_context(|| format!("write {}", destination.display()))?;
    }
    Ok(())
}
fn native_request(request: &[u8], dump_dir: Option<&Path>) -> Result<Vec<u8>> {
    #[cfg(all(target_os = "android", target_arch = "aarch64"))] { crate::keymint::request(request, dump_dir) }
    #[cfg(not(all(target_os = "android", target_arch = "aarch64")))] { let _ = (request, dump_dir); Err(DeviceRkpError::UnsupportedDevice("Android arm64 required".into()).into()) }
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::process::{Worker, detach_from_terminal};
    #[test]
    fn exchange_reads_are_bounded_and_reject_nonregular_files() {
        let dir = tempfile::tempdir().unwrap(); let file = dir.path().join("request.bin"); fs::write(&file, [1,2,3]).unwrap();
        assert_eq!(read_exchange_file(&file, 3).unwrap(), [1,2,3]);
        assert_eq!(crate::error::code_of(&read_exchange_file(&file, 2).unwrap_err()), "invalid_ta_response");
        assert!(read_exchange_file(dir.path(), 100).is_err());
        let link = dir.path().join("link.bin"); std::os::unix::fs::symlink(&file, &link).unwrap(); assert!(read_exchange_file(&link, 100).is_err());
    }
    #[test]
    fn worker_errors_keep_their_type_across_the_process_boundary() {
        for error in [DeviceRkpError::Rejected(-18), DeviceRkpError::Rejected(-10001), DeviceRkpError::InvalidResponse("invalid payload length".into()), DeviceRkpError::UnsupportedDevice("Android arm64 required".into()), DeviceRkpError::Transport("library cannot be loaded".into())] {
            let message = error.to_string(); let error: anyhow::Error = error.into(); let code = crate::error::code_of(&error);
            let encoded = serde_json::to_vec(&Reply::from_result(Err(error.context("vendor operation")))).unwrap();
            let returned = serde_json::from_slice::<Reply>(&encoded).unwrap().into_result().unwrap_err();
            assert_eq!(crate::error::code_of(&returned), code); assert_eq!(returned.to_string(), message);
        }
    }
    #[test]
    fn untyped_worker_errors_preserve_their_diagnostics() {
        let error = anyhow::anyhow!("dependency missing").context("load vendor library");
        let returned = Reply::from_result(Err(error)).into_result().unwrap_err(); assert_eq!(crate::error::code_of(&returned), "ta_transport_error"); assert!(returned.to_string().contains("load vendor library: dependency missing"));
    }
    #[test]
    fn worker_reply_payloads_are_bounded() {
        assert_eq!(Reply::Payload(vec![1,2,3]).into_result().unwrap(), vec![1,2,3]);
        assert_eq!(crate::error::code_of(&Reply::Payload(vec![0; BUFFER_SIZE+1]).into_result().unwrap_err()), "invalid_ta_response");
    }
    #[test]
    fn hex_dumps_are_readable_text_and_do_not_modify_the_binary_files() {
        let dir = tempfile::tempdir().unwrap(); fs::write(dir.path().join("request.bin"), [0x22,0x31,0,0]).unwrap(); fs::write(dir.path().join("response.bin"), [0xff,0]).unwrap(); dump_hex(dir.path()).unwrap();
        assert_eq!(fs::read_to_string(dir.path().join("request.hex")).unwrap(), "22310000"); assert_eq!(fs::read_to_string(dir.path().join("response.hex")).unwrap(), "ff00"); assert_eq!(fs::read(dir.path().join("request.bin")).unwrap(), [0x22,0x31,0,0]);
    }
    #[test]
    fn the_worker_leaves_the_callers_process_group() {
        let mut command = Command::new("sh"); command.args(["-c", "exec sleep 30"]); detach_from_terminal(&mut command); let child = command.spawn().unwrap(); let pid = child.id(); let _reaper = Worker(child);
        let listing = Command::new("ps").args(["-o", "pgid=", "-p", &pid.to_string()]).output().unwrap(); assert_eq!(String::from_utf8_lossy(&listing.stdout).trim(), pid.to_string());
    }
    #[test]
    fn a_broken_exchange_directory_is_a_transport_error() {
        let dir = tempfile::tempdir().unwrap(); let blocked = dir.path().join("tmp"); fs::write(&blocked, b"not a directory").unwrap(); let paths = AppPaths { tmp_dir: blocked, ..AppPaths::for_root(dir.path(), dir.path()) };
        let error = sign(&paths, &[0x22,0x31,0,0]).unwrap_err(); assert_eq!(crate::error::code_of(&error), "ta_transport_error"); assert!(error.to_string().contains("worker failed"));
    }
    #[test]
    fn a_worker_that_writes_no_reply_is_a_transport_error() {
        let dir = tempfile::tempdir().unwrap(); let paths = AppPaths::for_root(dir.path(), dir.path()); fs::create_dir_all(&paths.tmp_dir).unwrap(); assert_eq!(crate::error::code_of(&sign(&paths, &[0x22,0x31,0,0]).unwrap_err()), "ta_transport_error");
    }
    #[test]
    fn hung_worker_times_out_and_is_reaped() {
        let child = Command::new("sh").args(["-c", "exec sleep 30"]).spawn().unwrap(); let pid = child.id(); { let error = Worker(child).wait(Duration::from_millis(10)).unwrap_err(); assert_eq!(crate::error::code_of(&error), "ta_timeout"); }
        assert!(!Command::new("kill").args(["-0", &pid.to_string()]).output().unwrap().status.success());
    }
    #[test]
    fn diagnostic_is_generated_for_rejection_without_response() {
        let dir = tempfile::tempdir().unwrap(); let paths = AppPaths::for_root(dir.path(), dir.path()); let exchange = dir.path().join("exchange"); fs::create_dir(&exchange).unwrap();
        let result: Result<Vec<u8>> = Err(DeviceRkpError::Rejected(-20).into()); diagnostic(&exchange, &paths, &[0x1e,0x31,0,0], &result, Duration::from_millis(1)).unwrap();
        let report: serde_json::Value = serde_json::from_slice(&fs::read(exchange.join("report.json")).unwrap()).unwrap(); assert_eq!(report["command"], "0x311e"); assert_eq!(report["worker_success"], false); assert!(report["response"]["error"].is_string());
    }
}

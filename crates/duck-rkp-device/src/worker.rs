use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, process::Command, time::Duration};

use anyhow::{Context, Result};
use duck_core::AppPaths;
use serde::{Deserialize, Serialize};

use crate::{
    error::DeviceRkpError,
    process::{self, read_exchange_file},
    protocol::{self, BUFFER_SIZE, MAX_REQUEST_SIZE},
};

#[path = "worker_diagnostic.rs"]
mod diagnostic;

const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REPLY_FILE: usize = BUFFER_SIZE * 6;
const VENDOR_LIBRARY_PATH: &str =
    "/system/lib64:/vendor/lib64:/odm/lib64:/vendor/lib64/hw:/odm/lib64/hw";

#[derive(Serialize, Deserialize)]
enum Reply {
    Payload(Vec<u8>),
    Error(DeviceRkpError),
}

impl Reply {
    fn from_result(result: Result<Vec<u8>>) -> Self {
        match result {
            Ok(payload) => Self::Payload(payload),
            Err(error) => Self::Error(
                error
                    .downcast::<DeviceRkpError>()
                    .unwrap_or_else(|error| DeviceRkpError::Transport(format!("{error:#}"))),
            ),
        }
    }

    fn into_result(self) -> Result<Vec<u8>> {
        match self {
            Self::Payload(payload) if payload.len() <= BUFFER_SIZE => Ok(payload),
            Self::Payload(_) => {
                Err(DeviceRkpError::InvalidResponse("payload too large".into()).into())
            }
            Self::Error(error) => Err(error.into()),
        }
    }
}

pub(crate) fn sign(paths: &AppPaths, request: &[u8]) -> Result<Vec<u8>> {
    let local = |error: anyhow::Error| -> anyhow::Error {
        if error.is::<DeviceRkpError>() {
            error
        } else {
            DeviceRkpError::Transport(format!("device RKP worker failed: {error:#}")).into()
        }
    };
    fs::create_dir_all(&paths.tmp_dir)
        .with_context(|| format!("create {}", paths.tmp_dir.display()))
        .map_err(local)?;
    let exchange = tempfile::Builder::new()
        .prefix("rkp-device-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&paths.tmp_dir)?;
    fs::write(exchange.path().join("request.bin"), request)
        .context("write the worker request")
        .map_err(local)?;
    let started = std::time::Instant::now();
    let result = (|| -> Result<Vec<u8>> {
        let executable = std::env::current_exe()
            .context("locate this executable")
            .map_err(local)?;
        let mut command = Command::new(&executable);
        command
            .env("LD_LIBRARY_PATH", VENDOR_LIBRARY_PATH)
            .args(["rkp-device", "ta-csr", "--exchange"])
            .arg(exchange.path());
        let status = process::run(&mut command, TIMEOUT)?;
        let reply_path = exchange.path().join("reply.json");
        if !status.success() || !reply_path.is_file() {
            return Err(DeviceRkpError::Transport(format!(
                "worker exited with {status}; vendor ABI may be incompatible"
            ))
            .into());
        }
        let reply = read_exchange_file(&reply_path, MAX_REPLY_FILE).map_err(local)?;
        serde_json::from_slice::<Reply>(&reply)
            .context("parse the worker reply")
            .map_err(|error| DeviceRkpError::InvalidResponse(format!("{error:#}")))?
            .into_result()
    })();
    if let Err(error) =
        diagnostic::write(exchange.path(), paths, request, &result, started.elapsed())
    {
        eprintln!("RKP diagnostic unavailable: {error:#}");
    }
    preserve_exchange(exchange.path(), &paths.tmp_dir);
    result
}

fn preserve_exchange(exchange: &Path, tmp_dir: &Path) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    let destination = tmp_dir
        .join("rkp-device-debug")
        .join(format!("rkp-device-{stamp}"));
    if fs::create_dir_all(&destination).is_err() {
        return;
    }
    for name in ["request.bin", "response.bin", "reply.json", "report.json"] {
        let source = exchange.join(name);
        if source.is_file() {
            let _ = fs::copy(&source, destination.join(name));
        }
    }
}

pub(crate) fn execute(exchange: &Path) -> Result<()> {
    let result = (|| {
        let request = read_exchange_file(&exchange.join("request.bin"), MAX_REQUEST_SIZE)?;
        protocol::ta_payload(&request)?;
        native_request(&request, Some(exchange))
    })();
    let reply = Reply::from_result(result);
    let encoded = serde_json::to_vec(&reply).context("encode the worker reply")?;
    fs::write(exchange.join("reply.json"), encoded)
        .context("write the worker reply")
        .map_err(|error| DeviceRkpError::InvalidResponse(format!("{error:#}")))?;
    Ok(())
}

pub(crate) fn dump_hex(exchange: &Path) -> Result<()> {
    for name in ["request.bin", "response.bin"] {
        let source = exchange.join(name);
        let bytes = fs::read(&source).with_context(|| format!("read {}", source.display()))?;
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let destination = exchange.join(name.replace(".bin", ".hex"));
        fs::write(&destination, hex).with_context(|| format!("write {}", destination.display()))?;
    }
    Ok(())
}

fn native_request(request: &[u8], dump_dir: Option<&Path>) -> Result<Vec<u8>> {
    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    {
        crate::keymint::request(request, dump_dir)
    }
    #[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
    {
        let _ = (request, dump_dir);
        Err(DeviceRkpError::UnsupportedDevice("Android arm64 required".into()).into())
    }
}

#[cfg(all(test, unix))]
#[path = "worker_tests.rs"]
mod tests;

use super::*;
use crate::process::{Worker, detach_from_terminal};

#[test]
fn exchange_reads_are_bounded_and_reject_nonregular_files() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("request.bin");
    fs::write(&file, [1, 2, 3]).unwrap();
    assert_eq!(read_exchange_file(&file, 3).unwrap(), [1, 2, 3]);
    let error = read_exchange_file(&file, 2).unwrap_err();
    assert_eq!(crate::error::code_of(&error), "invalid_ta_response");
    assert!(read_exchange_file(dir.path(), 100).is_err());
    let link = dir.path().join("link.bin");
    symlink(&file, &link).unwrap();
    assert!(read_exchange_file(&link, 100).is_err());
}

#[test]
fn worker_errors_keep_their_type_across_the_process_boundary() {
    for error in [
        DeviceRkpError::Rejected(-18),
        DeviceRkpError::Rejected(-10001),
        DeviceRkpError::InvalidResponse("invalid payload length".into()),
        DeviceRkpError::UnsupportedDevice("Android arm64 required".into()),
        DeviceRkpError::Transport("library cannot be loaded".into()),
    ] {
        let expected_message = error.to_string();
        let error: anyhow::Error = error.into();
        let expected_code = crate::error::code_of(&error);
        let reply = Reply::from_result(Err(error.context("vendor operation")));
        let encoded = serde_json::to_vec(&reply).unwrap();
        let reply = serde_json::from_slice::<Reply>(&encoded).unwrap();
        let returned = reply.into_result().unwrap_err();
        assert_eq!(crate::error::code_of(&returned), expected_code);
        assert_eq!(returned.to_string(), expected_message);
    }
}

#[test]
fn untyped_worker_errors_preserve_their_diagnostics() {
    let error = anyhow::anyhow!("dependency missing").context("load vendor library");
    let returned = Reply::from_result(Err(error)).into_result().unwrap_err();
    assert_eq!(crate::error::code_of(&returned), "ta_transport_error");
    assert!(
        returned
            .to_string()
            .contains("load vendor library: dependency missing")
    );
}

#[test]
fn worker_reply_payloads_are_bounded() {
    assert_eq!(
        Reply::Payload(vec![1, 2, 3]).into_result().unwrap(),
        vec![1, 2, 3]
    );
    let error = Reply::Payload(vec![0; BUFFER_SIZE + 1])
        .into_result()
        .unwrap_err();
    assert_eq!(crate::error::code_of(&error), "invalid_ta_response");
}

#[test]
fn hex_dumps_are_readable_text_and_do_not_modify_the_binary_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("request.bin"), [0x22, 0x31, 0x00, 0x00]).unwrap();
    fs::write(dir.path().join("response.bin"), [0xff, 0x00]).unwrap();
    dump_hex(dir.path()).unwrap();
    assert_eq!(
        fs::read_to_string(dir.path().join("request.hex")).unwrap(),
        "22310000"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("response.hex")).unwrap(),
        "ff00"
    );
    assert_eq!(
        fs::read(dir.path().join("request.bin")).unwrap(),
        [0x22, 0x31, 0x00, 0x00]
    );
}

#[test]
fn the_worker_leaves_the_callers_process_group() {
    let mut command = Command::new("sh");
    command.args(["-c", "exec sleep 30"]);
    detach_from_terminal(&mut command);
    let child = command.spawn().unwrap();
    let pid = child.id();
    let _reaper = Worker(child);
    let listing = Command::new("ps")
        .args(["-o", "pgid=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    let group = String::from_utf8_lossy(&listing.stdout).trim().to_owned();
    assert_eq!(group, pid.to_string());
}

#[test]
fn a_broken_exchange_directory_is_a_transport_error() {
    let dir = tempfile::tempdir().unwrap();
    let blocked = dir.path().join("tmp");
    fs::write(&blocked, b"not a directory").unwrap();
    let paths = AppPaths {
        tmp_dir: blocked,
        ..AppPaths::for_root(dir.path(), dir.path())
    };
    let error = sign(&paths, &[0x22, 0x31, 0x00, 0x00]).unwrap_err();
    assert_eq!(crate::error::code_of(&error), "ta_transport_error");
    assert!(error.to_string().contains("worker failed"));
}

#[test]
fn a_worker_that_writes_no_reply_is_a_transport_error() {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_root(dir.path(), dir.path());
    fs::create_dir_all(&paths.tmp_dir).unwrap();
    let error = sign(&paths, &[0x22, 0x31, 0x00, 0x00]).unwrap_err();
    assert_eq!(crate::error::code_of(&error), "ta_transport_error");
}

#[test]
fn hung_worker_times_out_and_is_reaped() {
    let child = Command::new("sh")
        .args(["-c", "exec sleep 30"])
        .spawn()
        .unwrap();
    let pid = child.id();
    {
        let error = Worker(child).wait(Duration::from_millis(10)).unwrap_err();
        assert_eq!(crate::error::code_of(&error), "ta_timeout");
    }
    let output = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn diagnostic_is_generated_for_rejection_without_response() {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_root(dir.path(), dir.path());
    let exchange = dir.path().join("exchange");
    fs::create_dir(&exchange).unwrap();
    let result: Result<Vec<u8>> = Err(DeviceRkpError::Rejected(-20).into());
    diagnostic::write(
        &exchange,
        &paths,
        &[0x1e, 0x31, 0, 0],
        &result,
        Duration::from_millis(1),
    )
    .unwrap();
    let bytes = fs::read(exchange.join("report.json")).unwrap();
    let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(report["command"], "0x311e");
    assert_eq!(report["worker_success"], false);
    assert!(report["response"]["error"].is_string());
}

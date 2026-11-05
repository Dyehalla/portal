//! Exercise the shipped CLI boundary without installing a host service.
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

fn wizard(path: &std::path::Path, answers: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_portal-coordinator"))
        .args(["setup", "--dir"])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(answers.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}
#[test]
fn setup_command_writes_loadable_configuration_without_tokens_and_refuses_a_second_install() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("installation");
    let result = wizard(&path, "3\nlocalhost\n\n2\nнет\nда\n");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("https://localhost:8443"));
    assert!(output.contains("--config"));
    assert!(!output.contains("usr_"));
    let config = portal_coordinator::config::Config::load(&path.join("config.json")).unwrap();
    assert!(!config.state_dir.exists());
    let key = fs::read(&config.tls.key_file).unwrap();
    let result = wizard(&path, "3\n");
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("уже существует"));
    assert_eq!(fs::read(&config.tls.key_file).unwrap(), key);
}
#[test]
fn cancelling_and_eof_leave_no_installation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("cancelled");
    let result = wizard(&path, "3\nlocalhost\n\n2\nнет\nнет\n");
    assert!(result.status.success());
    assert!(!path.exists());
    let result = wizard(&path, "3\nlocalhost\n");
    assert!(!result.status.success());
    assert!(!path.exists());
}
#[test]
fn help_documents_both_startup_modes_and_bad_arguments_are_rejected() {
    let result = Command::new(env!("CARGO_BIN_EXE_portal-coordinator"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(result.status.success());
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("setup [--dir PATH]") && output.contains("--config PATH"));
    let result = Command::new(env!("CARGO_BIN_EXE_portal-coordinator"))
        .args(["setup", "--unknown"])
        .output()
        .unwrap();
    assert!(!result.status.success());
}

#[test]
fn existing_pem_pair_is_imported_without_modifying_source_files() {
    let temp = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = temp.path().join("source-cert.pem");
    let key_path = temp.path().join("source-key.pem");
    fs::write(&cert_path, cert.cert.pem()).unwrap();
    fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    let path = temp.path().join("import");
    let result = wizard(
        &path,
        &format!(
            "3\nlocalhost\n\n1\n{}\n{}\nнет\nда\n",
            cert_path.display(),
            key_path.display()
        ),
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(path.join("cert.pem")).unwrap(),
        fs::read(cert_path).unwrap()
    );
    assert_eq!(
        fs::read(path.join("key.pem")).unwrap(),
        fs::read(key_path).unwrap()
    );
}

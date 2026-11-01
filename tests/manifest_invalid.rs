//! Integration-level sanity checks for manifest validation: a malformed manifest
//! must never parse successfully.

use std::fs;

#[test]
fn invalid_manifest_is_rejected() {
    let dir = std::env::temp_dir().join(format!("dgp-manifest-invalid-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("service.yaml");
    fs::write(&path, "manifest_version: 99\nservice:\n  id: x\n").unwrap();
    let err = demo_ghostprovider::hoster::manifest::ServiceManifest::load_from_file(&path);
    assert!(err.is_err(), "invalid manifest must be rejected");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn empty_manifest_is_rejected() {
    let dir = std::env::temp_dir().join(format!("dgp-manifest-empty-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("service.yaml");
    fs::write(&path, "").unwrap();
    let err = demo_ghostprovider::hoster::manifest::ServiceManifest::load_from_file(&path);
    assert!(err.is_err(), "empty manifest must be rejected");
    let _ = fs::remove_dir_all(&dir);
}

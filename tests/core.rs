use rustsync::apply::{apply_manifest, ConflictPolicy};
use rustsync::scan::scan_root;
use std::fs;
use tempfile::tempdir;

#[test]
fn scans_and_applies_regular_files_atomically() {
    let source = tempdir().unwrap();
    let target = tempdir().unwrap();
    fs::create_dir(source.path().join("origin")).unwrap();
    fs::write(source.path().join("origin/file.txt"), b"rustsync core").unwrap();
    let mut permissions = fs::metadata(source.path().join("origin/file.txt"))
        .unwrap()
        .permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o640);
    }
    fs::set_permissions(source.path().join("origin/file.txt"), permissions).unwrap();

    let manifest = scan_root(source.path()).unwrap();
    manifest.validate().unwrap();
    apply_manifest(
        source.path(),
        target.path(),
        &manifest,
        ConflictPolicy::Overwrite,
    )
    .unwrap();
    assert_eq!(
        fs::read(target.path().join("origin/file.txt")).unwrap(),
        b"rustsync core"
    );
    let source_hash = scan_root(source.path()).unwrap().root_hash;
    let target_hash = scan_root(target.path()).unwrap().root_hash;
    assert_eq!(source_hash, target_hash);
}

#[test]
fn preserve_policy_keeps_existing_target() {
    let source = tempdir().unwrap();
    let target = tempdir().unwrap();
    fs::write(source.path().join("file"), b"remote").unwrap();
    fs::write(target.path().join("file"), b"local").unwrap();
    let manifest = scan_root(source.path()).unwrap();
    apply_manifest(
        source.path(),
        target.path(),
        &manifest,
        ConflictPolicy::Preserve,
    )
    .unwrap();
    assert_eq!(fs::read(target.path().join("file")).unwrap(), b"local");
}

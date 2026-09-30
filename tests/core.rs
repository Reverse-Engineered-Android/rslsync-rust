use rustsync::apply::{apply_manifest, apply_manifest_with_policy, ApplyPolicy, ConflictPolicy};
use rustsync::permissions::PermissionPolicy;
use rustsync::scan::{scan_root, scan_root_with_selection};
use rustsync::selective::SyncSelection;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime};
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
    // Pin the directory timestamp to a fixed past value: writing a child
    // refreshes a directory's mtime, so an apply that forgets to restore it
    // would otherwise compare equal whenever both trees land in the same
    // second and only fail at a second boundary.
    let pinned = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
    fs::File::open(source.path().join("origin"))
        .unwrap()
        .set_modified(pinned)
        .unwrap();

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
    assert_eq!(
        fs::metadata(target.path().join("origin"))
            .unwrap()
            .modified()
            .unwrap(),
        pinned
    );
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

#[test]
fn selection_prunes_excluded_directories() {
    let source = tempdir().unwrap();
    fs::create_dir_all(source.path().join("private/nested")).unwrap();
    fs::write(source.path().join("private/nested/key.txt"), b"secret").unwrap();
    fs::write(source.path().join("public.txt"), b"public").unwrap();
    let selection = SyncSelection::new(Vec::<String>::new(), ["private/**"]).unwrap();

    let manifest = scan_root_with_selection(source.path(), &selection).unwrap();
    assert_eq!(
        manifest
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        vec!["public.txt"]
    );
}

#[test]
fn permission_policies_control_only_metadata_application() {
    let source = tempdir().unwrap();
    let target = tempdir().unwrap();
    fs::write(source.path().join("file"), b"new").unwrap();
    fs::write(target.path().join("file"), b"old").unwrap();
    fs::set_permissions(
        source.path().join("file"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::set_permissions(
        target.path().join("file"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    let manifest = scan_root(source.path()).unwrap();

    apply_manifest_with_policy(
        source.path(),
        target.path(),
        &manifest,
        ApplyPolicy {
            conflict: ConflictPolicy::Overwrite,
            permissions: PermissionPolicy::Ignore,
        },
    )
    .unwrap();
    assert_eq!(fs::read(target.path().join("file")).unwrap(), b"new");
    assert_eq!(
        fs::metadata(target.path().join("file"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o666
    );

    fs::set_permissions(
        target.path().join("file"),
        fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    assert!(apply_manifest_with_policy(
        source.path(),
        target.path(),
        &manifest,
        ApplyPolicy {
            conflict: ConflictPolicy::Overwrite,
            permissions: PermissionPolicy::CheckOnly,
        },
    )
    .is_err());
}

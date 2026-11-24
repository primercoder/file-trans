use kite_core::Store;

#[cfg(unix)]
#[test]
fn store_and_parent_are_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("secrets");
    let path = directory.join("client.db");
    let _store = Store::open(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

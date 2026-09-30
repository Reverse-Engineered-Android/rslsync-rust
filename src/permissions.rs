use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionPolicy {
    Preserve,
    Ignore,
    CheckOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionRecord {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

pub fn read_permissions(path: &Path) -> Result<PermissionRecord> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(PermissionRecord {
        mode: metadata.permissions().mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
    })
}

pub fn apply_permissions(
    path: &Path,
    desired: PermissionRecord,
    policy: PermissionPolicy,
) -> Result<()> {
    if policy == PermissionPolicy::Ignore {
        return Ok(());
    }
    if policy == PermissionPolicy::CheckOnly {
        let actual = read_permissions(path)?;
        if actual != desired {
            anyhow::bail!(
                "permission mismatch for {}: mode {:o}, uid {}, gid {} (expected mode {:o}, uid {}, gid {})",
                path.display(),
                actual.mode,
                actual.uid,
                actual.gid,
                desired.mode,
                desired.uid,
                desired.gid
            );
        }
        return Ok(());
    }
    let actual = read_permissions(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(desired.mode))
        .with_context(|| format!("chmod {}", path.display()))?;
    if actual.uid != desired.uid || actual.gid != desired.gid {
        if let Err(error) = set_owner(path, desired.uid, desired.gid) {
            // A non-root process cannot change an arbitrary owner. Preserve the
            // owner we could not change and report it as a concrete limitation.
            let actual = read_permissions(path)?;
            if actual.uid != desired.uid || actual.gid != desired.gid {
                return Err(error);
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_owner(path: &Path, uid: u32, gid: u32) -> Result<()> {
    // Avoid libc as a dependency; this is the only ownership operation needed.
    let status = std::process::Command::new("chown")
        .arg(format!("{uid}:{gid}"))
        .arg(path)
        .status()
        .context("run chown")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("chown failed for {}", path.display())
    }
}

#[cfg(not(unix))]
fn set_owner(_path: &Path, _uid: u32, _gid: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn reads_and_checks_unix_permissions() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("file");
        fs::write(&path, b"x").unwrap();
        let record = read_permissions(&path).unwrap();
        apply_permissions(&path, record, PermissionPolicy::CheckOnly).unwrap();
    }
}

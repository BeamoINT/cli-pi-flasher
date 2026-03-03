use std::path::{Path, PathBuf};

use crate::{CoreError, CoreResult};

pub const DEFAULT_IMAGE_PATH: &str = "./rpi.img.xz";

pub fn app_root() -> PathBuf {
    if let Ok(v) = std::env::var("PIFLASHER_APP_ROOT") {
        return PathBuf::from(v);
    }

    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".piflasher");
    }

    if let Ok(profile) = std::env::var("USERPROFILE") {
        return PathBuf::from(profile).join(".piflasher");
    }

    PathBuf::from("./.piflasher")
}

pub fn ensure_layout(root: &Path) -> CoreResult<()> {
    std::fs::create_dir_all(root)?;
    std::fs::create_dir_all(root.join("image_cache"))?;
    std::fs::create_dir_all(root.join("reports"))?;
    std::fs::create_dir_all(root.join("logs"))?;
    Ok(())
}

pub fn policy_path(root: &Path) -> PathBuf {
    root.join("policy.toml")
}

pub fn agent_socket_path(root: &Path) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        // Use localhost TCP in initial cross-platform implementation.
        let _ = root;
        PathBuf::from("127.0.0.1:47550")
    }

    #[cfg(not(target_os = "windows"))]
    {
        root.join("agent.sock")
    }
}

pub fn run_lock_path(root: &Path) -> PathBuf {
    root.join("run.lock")
}

pub fn image_cache_root(root: &Path) -> PathBuf {
    root.join("image_cache")
}

pub fn reports_root(root: &Path) -> PathBuf {
    root.join("reports")
}

pub fn validate_root(root: &Path) -> CoreResult<()> {
    if root.as_os_str().is_empty() {
        return Err(CoreError::InvalidRequest("empty app root".to_string()));
    }
    Ok(())
}

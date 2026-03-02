use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use piflasher_protocol::PreparedImage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::paths::{ensure_layout, image_cache_root, DEFAULT_IMAGE_PATH};
use crate::{CoreError, CoreResult};

const BUF_SIZE: usize = 8 * 1024 * 1024;
const SOURCE_INDEX_FILE: &str = "source_index.json";

#[derive(Debug, Clone, Copy)]
pub struct ImagePrepareProgress {
    pub done_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SourceCacheEntry {
    source_size: u64,
    source_mtime_secs: i64,
    prepared: PreparedImage,
}

pub fn prepare_image(
    app_root: &Path,
    image_path: Option<&Path>,
    force: bool,
) -> CoreResult<PreparedImage> {
    prepare_image_impl(app_root, image_path, force, None)
}

pub fn prepare_image_with_progress<F>(
    app_root: &Path,
    image_path: Option<&Path>,
    force: bool,
    mut progress: F,
) -> CoreResult<PreparedImage>
where
    F: FnMut(ImagePrepareProgress),
{
    prepare_image_impl(app_root, image_path, force, Some(&mut progress))
}

fn prepare_image_impl(
    app_root: &Path,
    image_path: Option<&Path>,
    force: bool,
    mut progress: Option<&mut dyn FnMut(ImagePrepareProgress)>,
) -> CoreResult<PreparedImage> {
    ensure_layout(app_root)?;
    let source = image_path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_IMAGE_PATH));

    if !source.exists() {
        return Err(CoreError::ImagePreparation(format!(
            "image does not exist: {}",
            source.display()
        )));
    }

    let canonical_source = std::fs::canonicalize(&source).unwrap_or_else(|_| source.clone());
    let source_key = canonical_source.to_string_lossy().to_string();
    let source_meta = std::fs::metadata(&source)
        .map_err(|e| CoreError::ImagePreparation(format!("failed to read source metadata: {e}")))?;
    let source_size = source_meta.len();
    let source_mtime_secs = source_meta
        .modified()
        .ok()
        .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    emit_prepare_progress(&mut progress, 0, source_size);

    let cache_root = image_cache_root(app_root);
    std::fs::create_dir_all(&cache_root)?;
    let index_path = cache_root.join(SOURCE_INDEX_FILE);
    let mut source_index = load_source_index(&index_path)?;

    if !force {
        if let Some(prepared) =
            lookup_from_source_index(&source_index, &source_key, source_size, source_mtime_secs)
        {
            emit_prepare_progress(&mut progress, source_size, source_size);
            return Ok(prepared);
        }

        if let Some(prepared) =
            lookup_legacy_cache(&cache_root, &canonical_source, source_mtime_secs)?
        {
            source_index.insert(
                source_key,
                SourceCacheEntry {
                    source_size,
                    source_mtime_secs,
                    prepared: prepared.clone(),
                },
            );
            persist_source_index(&index_path, &source_index)?;
            emit_prepare_progress(&mut progress, source_size, source_size);
            return Ok(prepared);
        }
    }

    let temp_name = format!("tmp-{}.img", Uuid::new_v4());
    let temp_path = cache_root.join(temp_name);

    let mut out = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .open(&temp_path)
        .map_err(|e| CoreError::ImagePreparation(format!("failed to create temp image: {e}")))?;

    let mut blake = blake3::Hasher::new();
    let mut sha = Sha256::new();
    let mut bytes: u64 = 0;

    let ext = source
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or_default();
    if ext.eq_ignore_ascii_case("xz") {
        let file = File::open(&source)
            .map_err(|e| CoreError::ImagePreparation(format!("failed to open xz image: {e}")))?;
        let counter = CountingReader::new(file);
        let reader = BufReader::new(counter);
        let mut decoder = xz2::read::XzDecoder::new(reader);
        let mut buffer = vec![0u8; BUF_SIZE];
        loop {
            let n = decoder.read(&mut buffer).map_err(|e| {
                CoreError::ImagePreparation(format!("failed to decompress image: {e}"))
            })?;
            if n == 0 {
                break;
            }
            out.write_all(&buffer[..n]).map_err(|e| {
                CoreError::ImagePreparation(format!("failed to write cache image: {e}"))
            })?;
            blake.update(&buffer[..n]);
            sha.update(&buffer[..n]);
            bytes += n as u64;

            let compressed_done = decoder.get_ref().get_ref().bytes_read();
            emit_prepare_progress(&mut progress, compressed_done.min(source_size), source_size);
        }
    } else if ext.eq_ignore_ascii_case("img") {
        let mut file = File::open(&source)
            .map_err(|e| CoreError::ImagePreparation(format!("failed to open raw image: {e}")))?;
        let mut buffer = vec![0u8; BUF_SIZE];
        loop {
            let n = file.read(&mut buffer).map_err(|e| {
                CoreError::ImagePreparation(format!("failed to read raw image: {e}"))
            })?;
            if n == 0 {
                break;
            }
            out.write_all(&buffer[..n]).map_err(|e| {
                CoreError::ImagePreparation(format!("failed to write cache image: {e}"))
            })?;
            blake.update(&buffer[..n]);
            sha.update(&buffer[..n]);
            bytes += n as u64;
            emit_prepare_progress(&mut progress, bytes.min(source_size), source_size);
        }
    } else {
        return Err(CoreError::ImagePreparation(
            "unsupported image extension (expected .xz or .img)".to_string(),
        ));
    }

    out.flush()
        .map_err(|e| CoreError::ImagePreparation(format!("failed to flush cache image: {e}")))?;
    out.sync_all()
        .map_err(|e| CoreError::ImagePreparation(format!("failed to fsync cache image: {e}")))?;

    let blake3_hash = blake.finalize().to_hex().to_string();
    let sha256_hash = hex::encode(sha.finalize());

    let final_dir = cache_root.join(&blake3_hash);
    let final_img = final_dir.join("image.img");
    std::fs::create_dir_all(&final_dir)
        .map_err(|e| CoreError::ImagePreparation(format!("failed to create cache dir: {e}")))?;

    if final_img.exists() {
        if force {
            std::fs::remove_file(&final_img).map_err(|e| {
                CoreError::ImagePreparation(format!("failed to replace existing cache image: {e}"))
            })?;
        } else {
            let _ = std::fs::remove_file(&temp_path);
            let prepared = PreparedImage {
                original_path: source.to_string_lossy().to_string(),
                cache_image_path: final_img.to_string_lossy().to_string(),
                cache_dir: final_dir.to_string_lossy().to_string(),
                bytes,
                blake3: blake3_hash,
                sha256: sha256_hash,
                prepared_at: Utc::now(),
            };
            write_metadata(&final_dir, &prepared)?;
            source_index.insert(
                source_key,
                SourceCacheEntry {
                    source_size,
                    source_mtime_secs,
                    prepared: prepared.clone(),
                },
            );
            persist_source_index(&index_path, &source_index)?;
            emit_prepare_progress(&mut progress, source_size, source_size);
            return Ok(prepared);
        }
    }

    std::fs::rename(&temp_path, &final_img)
        .map_err(|e| CoreError::ImagePreparation(format!("failed to finalize cache image: {e}")))?;

    let prepared = PreparedImage {
        original_path: source.to_string_lossy().to_string(),
        cache_image_path: final_img.to_string_lossy().to_string(),
        cache_dir: final_dir.to_string_lossy().to_string(),
        bytes,
        blake3: blake3_hash,
        sha256: sha256_hash,
        prepared_at: Utc::now(),
    };
    write_metadata(&final_dir, &prepared)?;

    source_index.insert(
        source_key,
        SourceCacheEntry {
            source_size,
            source_mtime_secs,
            prepared: prepared.clone(),
        },
    );
    persist_source_index(&index_path, &source_index)?;

    emit_prepare_progress(&mut progress, source_size, source_size);
    Ok(prepared)
}

fn emit_prepare_progress(
    progress: &mut Option<&mut dyn FnMut(ImagePrepareProgress)>,
    done_bytes: u64,
    total_bytes: u64,
) {
    if let Some(cb) = progress.as_mut() {
        cb(ImagePrepareProgress {
            done_bytes,
            total_bytes,
        });
    }
}

fn lookup_from_source_index(
    index: &HashMap<String, SourceCacheEntry>,
    source_key: &str,
    source_size: u64,
    source_mtime_secs: i64,
) -> Option<PreparedImage> {
    let entry = index.get(source_key)?;
    if entry.source_size != source_size || entry.source_mtime_secs != source_mtime_secs {
        return None;
    }
    if !Path::new(&entry.prepared.cache_image_path).exists() {
        return None;
    }
    Some(entry.prepared.clone())
}

fn lookup_legacy_cache(
    cache_root: &Path,
    canonical_source: &Path,
    source_mtime_secs: i64,
) -> CoreResult<Option<PreparedImage>> {
    if !cache_root.exists() {
        return Ok(None);
    }

    for entry in std::fs::read_dir(cache_root)? {
        let entry = entry?;
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }

        let metadata_path = dir.join("metadata.json");
        if !metadata_path.exists() {
            continue;
        }

        let raw = match std::fs::read(&metadata_path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let prepared: PreparedImage = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if !Path::new(&prepared.cache_image_path).exists() {
            continue;
        }

        let prepared_source = match std::fs::canonicalize(&prepared.original_path) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if prepared_source != canonical_source {
            continue;
        }

        let cache_mtime_secs = std::fs::metadata(&prepared.cache_image_path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        if cache_mtime_secs < source_mtime_secs {
            continue;
        }

        return Ok(Some(prepared));
    }

    Ok(None)
}

fn write_metadata(cache_dir: &Path, prepared: &PreparedImage) -> CoreResult<()> {
    let metadata_path = cache_dir.join("metadata.json");
    let bytes = serde_json::to_vec_pretty(prepared)?;
    std::fs::write(metadata_path, bytes)?;
    Ok(())
}

fn load_source_index(path: &Path) -> CoreResult<HashMap<String, SourceCacheEntry>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let bytes = std::fs::read(path)?;
    let map = serde_json::from_slice(&bytes).unwrap_or_default();
    Ok(map)
}

fn persist_source_index(path: &Path, index: &HashMap<String, SourceCacheEntry>) -> CoreResult<()> {
    let bytes = serde_json::to_vec_pretty(index)?;
    std::fs::write(path, bytes)?;
    Ok(())
}

struct CountingReader<R> {
    inner: R,
    bytes_read: u64,
}

impl<R> CountingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            bytes_read: 0,
        }
    }

    fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read += n as u64;
        Ok(n)
    }
}

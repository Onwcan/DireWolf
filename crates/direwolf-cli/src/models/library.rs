//! The operator's model library (ADR-0072, Proposed): local model files,
//! held as immutable objects named by their SHA-256, and one manifest per
//! model that says what each file is.
//!
//! ```text
//! <root>/objects/sha256/<64 hex>   read-only, never executable, never replaced
//! <root>/manifests/<name>.json     written whole, then renamed: the commit
//! <root>/tmp/                      what an interrupted import left; emptied at open
//! <root>/lock                      one operation at a time
//! ```
//!
//! **What a manifest proves.** Each file's SHA-256 is computed here, from the
//! bytes copied into the library -- local consistency, never a publisher's
//! authenticity: an imported file has no trusted expected digest, and its
//! manifest says `LOCAL_DIGEST_ONLY`. Every name and path comes from the
//! operator's own command line or from the digest; nothing a file contains
//! names a path. Nothing here downloads, and nothing outside `<root>` is
//! written or removed.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use dwk_proto::json::{Number, Object, ParseOptions, Value, parse, to_canonical_bytes};
use sha2::{Digest as _, Sha256};

use super::format::{self, Format};

/// The manifest's schema.
const SCHEMA: &str = "direwolf.model-library.manifest";

/// The words a manifest may give a file's format: `Format::word`'s, no other.
const FILE_FORMATS: [&str; 5] = [
    "GGUF",
    "SAFETENSORS",
    "SAFETENSORS_INDEX",
    "JSON",
    "TOKENIZER_MODEL",
];

/// One file of a model, as its manifest records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Its plain file name, as imported.
    pub(crate) file: String,
    /// The SHA-256 of its bytes, computed locally.
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
    /// What it was found to be.
    pub(crate) format: String,
}

/// A model in the library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Manifest {
    pub(crate) name: String,
    pub(crate) files: Vec<Entry>,
    /// `GGUF` or `SAFETENSORS`: the weights' format.
    pub(crate) format: String,
    /// The quantisation the weights' own metadata names, if any.
    pub(crate) quantization: Option<String>,
    pub(crate) architecture: Option<String>,
    pub(crate) context_length: Option<u64>,
    pub(crate) block_count: Option<u64>,
    pub(crate) embedding_length: Option<u64>,
    pub(crate) head_count: Option<u64>,
    pub(crate) head_count_kv: Option<u64>,
    pub(crate) license: Option<String>,
}

impl Manifest {
    /// Every weight byte the model holds.
    pub(crate) fn weight_bytes(&self) -> u64 {
        self.files
            .iter()
            .filter(|e| e.format == "GGUF" || e.format == "SAFETENSORS")
            .fold(0u64, |sum, e| sum.saturating_add(e.bytes))
    }
}

/// The library at `root`, opened.
#[derive(Debug)]
pub(crate) struct Library {
    root: PathBuf,
}

/// Whether `name` is a model name: a lowercase letter or digit, then
/// lowercase letters, digits, `.`, `_` or `-`, at most 64 -- never a path.
pub(crate) fn is_model_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.len() <= 64
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
        && !name.contains("..")
}

fn is_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            out.push(char::from(
                DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    out
}

/// A held lock, released when dropped.
struct Locked(PathBuf);

impl Drop for Locked {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(unix)]
fn private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn private_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Read-only and never executable: what every object is.
#[cfg(unix)]
fn seal(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o444))
}

#[cfg(not(unix))]
fn seal(file: &File) -> io::Result<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(true);
    file.set_permissions(permissions)
}

#[cfg(unix)]
fn executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
const fn executable(_meta: &fs::Metadata) -> bool {
    false
}

/// A file name for `tmp/` no other import of this process shares.
fn fresh(tag: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(
        "{tag}-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Copy `from` into a new file at `to`, hashing what is written: the digest
/// is of the bytes the library holds, never of a second read of the source.
fn copy_hashing(from: &Path, to: &Path) -> Result<(String, u64), String> {
    let mut source = File::open(from).map_err(|e| format!("{}: {e}", from.display()))?;
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)
        .map_err(|e| format!("the library's tmp: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("{}: {e}", from.display())),
        };
        let chunk = buffer.get(..n).unwrap_or_default();
        hasher.update(chunk);
        target
            .write_all(chunk)
            .map_err(|e| format!("writing the library: {e}"))?;
        total = total.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
    target
        .sync_all()
        .map_err(|e| format!("syncing the library: {e}"))?;
    seal(&target).map_err(|e| format!("sealing an object: {e}"))?;
    Ok((hex(&hasher.finalize()), total))
}

/// The SHA-256 and length of a file the library holds, read now.
fn digest_of(path: &Path) -> Result<(String, u64), String> {
    let mut file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        hasher.update(buffer.get(..n).unwrap_or_default());
        total = total.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
    Ok((hex(&hasher.finalize()), total))
}

/// One staged file: its name, digest, length, format, and whether its
/// object was made by this import.
type Staged = (String, String, u64, Format, bool);

/// What `verify` found of one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FileState {
    /// Its bytes hash to its recorded digest, at its recorded length.
    Verified,
    /// Absent, not a regular file (a symlink, a directory), executable, of
    /// another length or another digest.
    Corrupt(String),
}

impl Library {
    /// Open the library at `root` -- absolute, a real directory, not a
    /// symlink -- creating its directories, private, and emptying `tmp/`.
    pub(crate) fn open(root: &Path) -> Result<Self, String> {
        if !root.is_absolute() {
            return Err("--library must be an absolute path".to_owned());
        }
        if let Ok(meta) = fs::symlink_metadata(root)
            && !meta.is_dir()
        {
            return Err(format!(
                "{} is not a directory (a symlink is never followed)",
                root.display()
            ));
        }
        for dir in [
            root.to_path_buf(),
            root.join("objects"),
            root.join("objects").join("sha256"),
            root.join("manifests"),
            root.join("tmp"),
        ] {
            match fs::symlink_metadata(&dir) {
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => return Err(format!("{} is not a directory", dir.display())),
                Err(_) => {
                    fs::create_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                    private_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                }
            }
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn lock(&self) -> Result<Locked, String> {
        let path = self.root.join("lock");
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let _ = writeln!(file, "{}", std::process::id());
                Ok(Locked(path))
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(format!(
                "another operation holds the library ({}); if no `direwolf models` runs, \
                 remove that file",
                path.display()
            )),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// What an interrupted operation left in `tmp/`: never referenced, so
    /// removed. Called under the lock.
    fn sweep(&self) {
        if let Ok(entries) = fs::read_dir(self.root.join("tmp")) {
            for entry in entries.flatten() {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    fn object(&self, digest: &str) -> PathBuf {
        self.root.join("objects").join("sha256").join(digest)
    }

    fn manifest_path(&self, name: &str) -> PathBuf {
        self.root.join("manifests").join(format!("{name}.json"))
    }

    /// Import `files` -- one model's weights and their companions -- as
    /// `name`. Refused, with nothing kept, unless every file is a format this
    /// build reads, the weights are one format, a split or sharded model is
    /// whole, and the library holds no model of that name already.
    pub(crate) fn import(
        &self,
        name: &str,
        files: &[PathBuf],
        quota: Option<u64>,
    ) -> Result<Manifest, String> {
        if !is_model_name(name) {
            return Err(format!(
                "{name:?} is not a model name (a-z, 0-9, ., _, -; at most 64)"
            ));
        }
        if files.is_empty() {
            return Err("no file to import".to_owned());
        }
        let _locked = self.lock()?;
        self.sweep();
        if fs::symlink_metadata(self.manifest_path(name)).is_ok() {
            return Err(format!(
                "{name} is in the library already: an installed model is never replaced; \
                 remove it first"
            ));
        }
        let mut names: Vec<String> = Vec::new();
        let mut total = 0u64;
        for file in files {
            let plain = file
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|n| format::is_plain_name(n))
                .ok_or_else(|| format!("{}: not a plain file name", file.display()))?;
            if names.iter().any(|n| n == plain) {
                return Err(format!("{plain} is named twice"));
            }
            names.push(plain.to_owned());
            let meta =
                fs::symlink_metadata(file).map_err(|e| format!("{}: {e}", file.display()))?;
            if !meta.is_file() {
                return Err(format!(
                    "{}: not a regular file (a symlink is never followed)",
                    file.display()
                ));
            }
            total = total.saturating_add(meta.len());
        }
        if let Some(quota) = quota {
            let held = self.held_bytes();
            if held.saturating_add(total) > quota {
                return Err(format!(
                    "the library holds {held} bytes; {total} more would pass its quota of {quota}"
                ));
            }
        }
        let mut kept: Vec<Staged> = Vec::new();
        let manifest = self
            .stage(files, &names, &mut kept)
            .and_then(|()| whole(name, &kept));
        let manifest = match manifest {
            Ok(manifest) => manifest,
            Err(why) => {
                // Nothing of a refused import is kept: the objects it made
                // that no manifest names go.
                let referenced = self.referenced();
                for (_, digest, _, _, fresh_object) in &kept {
                    if *fresh_object && !referenced.contains(digest) {
                        let _ = fs::remove_file(self.object(digest));
                    }
                }
                return Err(why);
            }
        };
        self.write_manifest(&manifest)?;
        Ok(manifest)
    }

    /// Copy each file in, hashing what is written, then identify the copy:
    /// what is identified is exactly what is kept.
    fn stage(
        &self,
        files: &[PathBuf],
        names: &[String],
        kept: &mut Vec<Staged>,
    ) -> Result<(), String> {
        for (file, plain) in files.iter().zip(names) {
            let staged = self.root.join("tmp").join(fresh("import"));
            let (digest, bytes) = copy_hashing(file, &staged)?;
            let object = self.object(&digest);
            let fresh_object = if fs::symlink_metadata(&object).is_ok() {
                let _ = fs::remove_file(&staged);
                false
            } else {
                fs::rename(&staged, &object).map_err(|e| format!("placing an object: {e}"))?;
                true
            };
            let staged_name = self.root.join("tmp").join(fresh("identify"));
            // Identify through the object, under the file's own name (the
            // name decides safetensors and JSON): a hard link, removed after.
            let identified = if fs::hard_link(&object, &staged_name).is_ok() {
                let named = self.root.join("tmp").join(fresh("named"));
                fs::create_dir(&named).map_err(|e| format!("the library's tmp: {e}"))?;
                let at = named.join(plain);
                let result = fs::rename(&staged_name, &at)
                    .map_err(|e| format!("the library's tmp: {e}"))
                    .and_then(|()| format::identify(&at));
                let _ = fs::remove_file(&at);
                let _ = fs::remove_dir(&named);
                result
            } else {
                Err("the library cannot link its own object".to_owned())
            };
            let format = match identified {
                Ok(format) => format,
                Err(why) => {
                    // Not yet in `kept`, so the import's own clean-up would
                    // miss it: a refused file's object, if this import made
                    // it, goes now.
                    if fresh_object {
                        let _ = fs::remove_file(&object);
                    }
                    return Err(format!("{plain}: {why}"));
                }
            };
            kept.push((plain.clone(), digest, bytes, format, fresh_object));
        }
        Ok(())
    }

    fn held_bytes(&self) -> u64 {
        fs::read_dir(self.root.join("objects").join("sha256"))
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|e| e.metadata().ok())
                    .fold(0u64, |sum, m| sum.saturating_add(m.len()))
            })
            .unwrap_or(0)
    }

    fn write_manifest(&self, manifest: &Manifest) -> Result<(), String> {
        let staged = self.root.join("tmp").join(fresh("manifest"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)
            .map_err(|e| format!("the library's tmp: {e}"))?;
        file.write_all(&to_canonical_bytes(&encode(manifest)))
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("writing a manifest: {e}"))?;
        fs::rename(&staged, self.manifest_path(&manifest.name))
            .map_err(|e| format!("committing a manifest: {e}"))?;
        if let Ok(dir) = File::open(self.root.join("manifests")) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    /// Every model, by name.
    pub(crate) fn list(&self) -> Result<Vec<Manifest>, String> {
        let mut out = Vec::new();
        let entries =
            fs::read_dir(self.root.join("manifests")).map_err(|e| format!("manifests: {e}"))?;
        for entry in entries.flatten() {
            let file = entry.file_name();
            let Some(name) = file.to_str().and_then(|n| n.strip_suffix(".json")) else {
                continue;
            };
            if is_model_name(name) {
                out.push(self.read(name)?);
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// One model's manifest.
    pub(crate) fn read(&self, name: &str) -> Result<Manifest, String> {
        if !is_model_name(name) {
            return Err(format!("{name:?} is not a model name"));
        }
        let path = self.manifest_path(name);
        let meta =
            fs::symlink_metadata(&path).map_err(|_| format!("{name} is not in the library"))?;
        if !meta.is_file() {
            return Err(format!("{}: not a regular file", path.display()));
        }
        let mut bytes = Vec::new();
        File::open(&path)
            .and_then(|f| f.take(1 << 20).read_to_end(&mut bytes))
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let value = parse(&bytes, ParseOptions::dwkp())
            .map_err(|e| format!("{}: not a manifest: {e}", path.display()))?;
        decode(&value).ok_or_else(|| format!("{}: not a manifest", path.display()))
    }

    /// Hash every file of `name` again.
    pub(crate) fn verify(&self, name: &str) -> Result<Vec<(Entry, FileState)>, String> {
        let manifest = self.read(name)?;
        Ok(manifest
            .files
            .iter()
            .map(|entry| {
                let path = self.object(&entry.sha256);
                let state = match fs::symlink_metadata(&path) {
                    Err(_) => FileState::Corrupt("absent".to_owned()),
                    Ok(meta) if !meta.is_file() => {
                        FileState::Corrupt("not a regular file".to_owned())
                    }
                    Ok(meta) if executable(&meta) => FileState::Corrupt("executable".to_owned()),
                    Ok(meta) if meta.len() != entry.bytes => {
                        FileState::Corrupt(format!("{} bytes, not {}", meta.len(), entry.bytes))
                    }
                    Ok(_) => match digest_of(&path) {
                        Ok((digest, _)) if digest == entry.sha256 => FileState::Verified,
                        Ok((digest, _)) => FileState::Corrupt(format!("sha256 {digest}")),
                        Err(why) => FileState::Corrupt(why),
                    },
                };
                (entry.clone(), state)
            })
            .collect())
    }

    fn referenced(&self) -> Vec<String> {
        self.list()
            .map(|all| {
                all.iter()
                    .flat_map(|m| m.files.iter().map(|e| e.sha256.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remove `name`'s manifest, then every object no manifest names: only
    /// `<root>/objects/sha256/<digest>` files are ever removed.
    pub(crate) fn remove(&self, name: &str) -> Result<u64, String> {
        let _locked = self.lock()?;
        self.read(name)?;
        fs::remove_file(self.manifest_path(name)).map_err(|e| format!("{name}: {e}"))?;
        let referenced = self.referenced();
        let mut removed = 0u64;
        if let Ok(entries) = fs::read_dir(self.root.join("objects").join("sha256")) {
            for entry in entries.flatten() {
                let file = entry.file_name();
                let Some(digest) = file.to_str().filter(|d| is_digest(d)) else {
                    continue;
                };
                if !referenced.iter().any(|r| r == digest)
                    && fs::remove_file(self.object(digest)).is_ok()
                {
                    removed = removed.saturating_add(1);
                }
            }
        }
        Ok(removed)
    }
}

/// The model `kept` makes, or why it is not one: one weights format, every
/// part of a split GGUF and every shard an index names, nothing executable.
fn whole(name: &str, kept: &[Staged]) -> Result<Manifest, String> {
    let ggufs: Vec<&format::GgufFacts> = kept
        .iter()
        .filter_map(|(_, _, _, f, _)| match f {
            Format::Gguf(facts) => Some(facts),
            _ => None,
        })
        .collect();
    let shards: Vec<&str> = kept
        .iter()
        .filter(|(_, _, _, f, _)| matches!(f, Format::Safetensors(_)))
        .map(|(n, _, _, _, _)| n.as_str())
        .collect();
    let indexed: Vec<&Vec<String>> = kept
        .iter()
        .filter_map(|(_, _, _, f, _)| match f {
            Format::SafetensorsIndex(names) => Some(names),
            _ => None,
        })
        .collect();
    let format = match (ggufs.is_empty(), shards.is_empty()) {
        (false, true) => "GGUF",
        (true, false) => "SAFETENSORS",
        (true, true) => return Err("no weights: a GGUF or safetensors file is required".to_owned()),
        (false, false) => return Err("GGUF and safetensors weights in one model".to_owned()),
    };
    if format == "GGUF" {
        let splits: Vec<(u64, u64)> = ggufs.iter().filter_map(|f| f.split).collect();
        if let Some((_, count)) = splits.first() {
            if splits.len() != ggufs.len() || splits.iter().any(|(_, c)| c != count) {
                return Err("parts of different split GGUF files".to_owned());
            }
            for part in 0..*count {
                if !splits.iter().any(|(no, _)| *no == part) {
                    return Err(format!(
                        "split GGUF part {} of {count} is missing",
                        part.saturating_add(1)
                    ));
                }
            }
            if u64::try_from(splits.len()).ok() != Some(*count) {
                return Err("a split GGUF part is given twice".to_owned());
            }
        } else if ggufs.len() > 1 {
            return Err("several GGUF files that are not parts of one".to_owned());
        }
    } else {
        match indexed.as_slice() {
            [] if shards.len() == 1 => {}
            [] => return Err("several safetensors shards and no index naming them".to_owned()),
            [names] => {
                for shard in names.iter() {
                    if !shards.contains(&shard.as_str()) {
                        return Err(format!("shard {shard} the index names is missing"));
                    }
                }
                for shard in &shards {
                    if !names.iter().any(|n| n == shard) {
                        return Err(format!("shard {shard} is not in the index"));
                    }
                }
            }
            _ => return Err("more than one safetensors index".to_owned()),
        }
    }
    let first = ggufs.first();
    let pick = |f: fn(&format::GgufFacts) -> Option<u64>| first.and_then(|g| f(g));
    Ok(Manifest {
        name: name.to_owned(),
        files: kept
            .iter()
            .map(|(file, digest, bytes, f, _)| Entry {
                file: file.clone(),
                sha256: digest.clone(),
                bytes: *bytes,
                format: f.word().to_owned(),
            })
            .collect(),
        format: format.to_owned(),
        quantization: first.and_then(|g| g.quantization()),
        architecture: first.and_then(|g| g.architecture.clone()),
        context_length: pick(|g| g.context_length),
        block_count: pick(|g| g.block_count),
        embedding_length: pick(|g| g.embedding_length),
        head_count: pick(|g| g.head_count),
        head_count_kv: pick(|g| g.head_count_kv),
        license: first.and_then(|g| g.license.clone()),
    })
}

fn text(value: Option<&String>) -> Value {
    value.map_or(Value::Null, |t| Value::String(t.clone()))
}

fn number(value: Option<u64>) -> Value {
    value
        .and_then(|n| i64::try_from(n).ok())
        .map_or(Value::Null, |n| Value::Number(Number::Int(n)))
}

fn object(members: Vec<(&str, Value)>) -> Value {
    let mut out = Object::new();
    for (key, value) in members {
        // Keys here are this module's own constants, each once.
        let _ = out.insert(key.to_owned(), value);
    }
    Value::Object(out)
}

/// A manifest as JSON. Its states are said separately, never as one score:
/// verified locally, publisher authenticity unknown, a format this build
/// reads, a backend by format only, and never ready for inference here.
fn encode(m: &Manifest) -> Value {
    let files = m
        .files
        .iter()
        .map(|e| {
            object(vec![
                ("file", Value::String(e.file.clone())),
                ("sha256", Value::String(e.sha256.clone())),
                ("bytes", number(Some(e.bytes))),
                ("format", Value::String(e.format.clone())),
            ])
        })
        .collect();
    let backend = if m.format == "GGUF" {
        "llama.cpp (by format; no server checked)"
    } else {
        "none in this build"
    };
    object(vec![
        ("schema", Value::String(SCHEMA.to_owned())),
        ("schema_version", number(Some(1))),
        ("name", Value::String(m.name.clone())),
        ("source", Value::String("local-import".to_owned())),
        ("files", Value::Array(files)),
        ("format", Value::String(m.format.clone())),
        ("quantization", text(m.quantization.as_ref())),
        ("architecture", text(m.architecture.as_ref())),
        ("context_length", number(m.context_length)),
        ("block_count", number(m.block_count)),
        ("embedding_length", number(m.embedding_length)),
        ("head_count", number(m.head_count)),
        ("head_count_kv", number(m.head_count_kv)),
        ("license", text(m.license.as_ref())),
        (
            "states",
            object(vec![
                ("downloaded", Value::Bool(false)),
                ("verified", Value::String("LOCAL_DIGEST_ONLY".to_owned())),
                ("publisher_authenticated", Value::Bool(false)),
                ("format_supported", Value::Bool(true)),
                ("backend_compatible", Value::String(backend.to_owned())),
                ("ready_for_inference", Value::Bool(false)),
            ]),
        ),
    ])
}

fn decode(value: &Value) -> Option<Manifest> {
    let Value::Object(o) = value else {
        return None;
    };
    let string = |key: &str| match o.get(key) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    };
    let unsigned = |key: &str| match o.get(key) {
        Some(Value::Number(Number::Int(n))) => u64::try_from(*n).ok(),
        _ => None,
    };
    if string("schema").as_deref() != Some(SCHEMA) || unsigned("schema_version") != Some(1) {
        return None;
    }
    let Some(Value::Array(files)) = o.get("files") else {
        return None;
    };
    let mut entries = Vec::new();
    for file in files {
        let Value::Object(f) = file else {
            return None;
        };
        let get = |key: &str| match f.get(key) {
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        };
        let bytes = match f.get("bytes") {
            Some(Value::Number(Number::Int(n))) => u64::try_from(*n).ok()?,
            _ => return None,
        };
        let entry = Entry {
            file: get("file").filter(|n| format::is_plain_name(n))?,
            sha256: get("sha256").filter(|d| is_digest(d))?,
            bytes,
            format: get("format").filter(|f| FILE_FORMATS.contains(&f.as_str()))?,
        };
        entries.push(entry);
    }
    Some(Manifest {
        name: string("name").filter(|n| is_model_name(n))?,
        files: entries,
        format: string("format").filter(|f| f == "GGUF" || f == "SAFETENSORS")?,
        quantization: string("quantization"),
        architecture: string("architecture"),
        context_length: unsigned("context_length"),
        block_count: unsigned("block_count"),
        embedding_length: unsigned("embedding_length"),
        head_count: unsigned("head_count"),
        head_count_kv: unsigned("head_count_kv"),
        license: string("license"),
    })
}

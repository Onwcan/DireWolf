//! `direwolf models` (ADR-0072, Proposed): the readers on hand-built headers
//! -- valid, truncated, oversized, disguised -- the library on real files in
//! a scratch directory, and the estimates on fixed facts for each platform.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};

use super::format::{self, Format};
use super::hardware::{self, Facts, Headroom};
#[cfg(unix)]
use super::library::AFTER_CHECK;
use super::library::{FileState, Library, Manifest, copy_hashing, is_model_name};
use super::{EXIT_REFUSED, EXIT_USAGE, json_line, run, shown};

/// A directory removed when dropped, read-only files included.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "dw-models-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    fn library(&self) -> Library {
        Library::open(&self.0.join("library")).unwrap()
    }

    fn objects(&self) -> Vec<String> {
        let mut out: Vec<String> = fs::read_dir(self.0.join("library/objects/sha256"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        out.sort();
        out
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fn writable(path: &Path) {
            if let Ok(meta) = fs::symlink_metadata(path) {
                if meta.is_dir() {
                    if let Ok(entries) = fs::read_dir(path) {
                        for e in entries.flatten() {
                            writable(&e.path());
                        }
                    }
                } else if meta.is_file() {
                    let mut p = meta.permissions();
                    #[allow(clippy::permissions_set_readonly_false)]
                    p.set_readonly(false);
                    let _ = fs::set_permissions(path, p);
                }
            }
        }
        writable(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ---- GGUF, built by hand --------------------------------------------------------

enum Kv {
    U32(u32),
    U64(u64),
    Str(&'static str),
    Strings(Vec<&'static str>),
    U32s(Vec<u32>),
    /// A type number and its raw bytes, for the reader's refusals.
    Raw(u32, Vec<u8>),
}

fn gstr(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&u64::try_from(s.len()).unwrap().to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn gguf(version: u32, kvs: &[(&str, Kv)]) -> Vec<u8> {
    let mut out = b"GGUF".to_vec();
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&u64::try_from(kvs.len()).unwrap().to_le_bytes());
    for (key, value) in kvs {
        gstr(&mut out, key);
        match value {
            Kv::U32(n) => {
                out.extend_from_slice(&4u32.to_le_bytes());
                out.extend_from_slice(&n.to_le_bytes());
            }
            Kv::U64(n) => {
                out.extend_from_slice(&10u32.to_le_bytes());
                out.extend_from_slice(&n.to_le_bytes());
            }
            Kv::Str(s) => {
                out.extend_from_slice(&8u32.to_le_bytes());
                gstr(&mut out, s);
            }
            Kv::Strings(items) => {
                out.extend_from_slice(&9u32.to_le_bytes());
                out.extend_from_slice(&8u32.to_le_bytes());
                out.extend_from_slice(&u64::try_from(items.len()).unwrap().to_le_bytes());
                for s in items {
                    gstr(&mut out, s);
                }
            }
            Kv::U32s(items) => {
                out.extend_from_slice(&9u32.to_le_bytes());
                out.extend_from_slice(&4u32.to_le_bytes());
                out.extend_from_slice(&u64::try_from(items.len()).unwrap().to_le_bytes());
                for n in items {
                    out.extend_from_slice(&n.to_le_bytes());
                }
            }
            Kv::Raw(kind, bytes) => {
                out.extend_from_slice(&kind.to_le_bytes());
                out.extend_from_slice(bytes);
            }
        }
    }
    out
}

fn llama(file_type: u32, extra: Vec<(&'static str, Kv)>) -> Vec<u8> {
    let mut kvs = vec![
        ("general.architecture", Kv::Str("llama")),
        ("general.name", Kv::Str("tiny")),
        ("general.license", Kv::Str("apache-2.0")),
        ("general.file_type", Kv::U32(file_type)),
        ("llama.context_length", Kv::U32(8192)),
        ("llama.block_count", Kv::U32(32)),
        ("llama.embedding_length", Kv::U32(4096)),
        ("llama.attention.head_count", Kv::U32(32)),
        ("llama.attention.head_count_kv", Kv::U32(8)),
        (
            "tokenizer.ggml.tokens",
            Kv::Strings(vec!["<s>", "</s>", "a"]),
        ),
        ("tokenizer.ggml.token_type", Kv::U32s(vec![1, 1, 1])),
    ];
    kvs.extend(extra);
    gguf(3, &kvs)
}

#[test]
fn a_gguf_header_is_read_for_its_facts_and_its_own_quantization() {
    let s = Scratch::new("gguf");
    for (file_type, quant) in [
        (2, "Q4_0"),
        (15, "Q4_K_M"),
        (8, "Q5_0"),
        (17, "Q5_K_M"),
        (7, "Q8_0"),
    ] {
        let path = s.file("m.gguf", &llama(file_type, vec![]));
        let Ok(Format::Gguf(g)) = format::identify(&path) else {
            panic!("not read")
        };
        assert_eq!(g.quantization().as_deref(), Some(quant));
        assert_eq!(g.architecture.as_deref(), Some("llama"));
        assert_eq!(g.name.as_deref(), Some("tiny"));
        assert_eq!(g.license.as_deref(), Some("apache-2.0"));
        assert_eq!(
            (
                g.context_length,
                g.block_count,
                g.embedding_length,
                g.head_count,
                g.head_count_kv
            ),
            (Some(8192), Some(32), Some(4096), Some(32), Some(8))
        );
        assert_eq!(g.split, None);
    }
    // A file's name is never its quantisation: a Q8 file named Q4 is Q8.
    let path = s.file("model-Q4_K_M.gguf", &llama(7, vec![]));
    let Ok(Format::Gguf(g)) = format::identify(&path) else {
        panic!()
    };
    assert_eq!(g.quantization().as_deref(), Some("Q8_0"));
    // No file_type: no quantisation claimed.
    let path = s.file(
        "plain.gguf",
        &gguf(3, &[("general.architecture", Kv::Str("x"))]),
    );
    let Ok(Format::Gguf(g)) = format::identify(&path) else {
        panic!()
    };
    assert_eq!(g.quantization(), None);
}

#[test]
fn a_corrupt_or_hostile_gguf_header_is_refused() {
    let s = Scratch::new("gguf-bad");
    let good = llama(15, vec![]);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("truncated", good.get(..good.len() - 5).unwrap().to_vec()),
        ("version", gguf(9, &[])),
        ("unknown type", gguf(3, &[("k", Kv::Raw(99, vec![0; 8]))])),
        (
            "huge string",
            gguf(3, &[("k", Kv::Raw(8, u64::MAX.to_le_bytes().to_vec()))]),
        ),
        (
            "array of arrays",
            gguf(
                3,
                &[(
                    "k",
                    Kv::Raw(
                        9,
                        [9u32.to_le_bytes().to_vec(), 1u64.to_le_bytes().to_vec()].concat(),
                    ),
                )],
            ),
        ),
        (
            "huge array",
            gguf(
                3,
                &[(
                    "k",
                    Kv::Raw(
                        9,
                        [4u32.to_le_bytes().to_vec(), u64::MAX.to_le_bytes().to_vec()].concat(),
                    ),
                )],
            ),
        ),
        (
            "split disagrees",
            gguf(3, &[("split.no", Kv::U32(3)), ("split.count", Kv::U32(2))]),
        ),
        (
            "split unbounded",
            gguf(
                3,
                &[("split.no", Kv::U32(0)), ("split.count", Kv::U64(u64::MAX))],
            ),
        ),
        ("no magic", b"GGUX\x03\0\0\0".to_vec()),
    ];
    for (case, bytes) in cases {
        let path = s.file("m.gguf", &bytes);
        assert!(format::identify(&path).is_err(), "{case}");
    }
    let mut many_keys = b"GGUF".to_vec();
    many_keys.extend_from_slice(&3u32.to_le_bytes());
    many_keys.extend_from_slice(&0u64.to_le_bytes());
    many_keys.extend_from_slice(&u64::MAX.to_le_bytes());
    assert!(format::identify(&s.file("k.gguf", &many_keys)).is_err());
}

#[test]
fn pickles_and_archives_are_refused_by_their_bytes_whatever_their_names() {
    let s = Scratch::new("pickle");
    let pickle = b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00}\x94.".to_vec();
    for name in ["pytorch_model.bin", "model.pt", "model.pkl", "weights.dat"] {
        let why = format::identify(&s.file(name, &pickle)).unwrap_err();
        assert!(why.contains("pickle"), "{name}: {why}");
    }
    // Disguised as a supported format: its header does not hold.
    assert!(format::identify(&s.file("model.safetensors", &pickle)).is_err());
    assert!(format::identify(&s.file("model.gguf", &pickle)).is_err());
    let zip = b"PK\x03\x04\x14\x00\x00\x00archive/data.pkl".to_vec();
    let why = format::identify(&s.file("model.bin", &zip)).unwrap_err();
    assert!(why.contains("zip"), "{why}");
    // Code is never a model.
    for name in ["modeling.py", "setup.sh", "model.onnx", "README.md"] {
        assert!(
            format::identify(&s.file(name, b"import os\n")).is_err(),
            "{name}"
        );
    }
}

fn safetensors(header: &str, data: usize) -> Vec<u8> {
    let mut out = u64::try_from(header.len()).unwrap().to_le_bytes().to_vec();
    out.extend_from_slice(header.as_bytes());
    out.extend(std::iter::repeat_n(0u8, data));
    out
}

#[test]
fn a_safetensors_header_must_index_every_byte_exactly() {
    let s = Scratch::new("st");
    let ok = r#"{"__metadata__":{"format":"pt"},"a":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]},"b":{"dtype":"BF16","shape":[4],"data_offsets":[16,24]}}"#;
    let Ok(Format::Safetensors(facts)) =
        format::identify(&s.file("m.safetensors", &safetensors(ok, 24)))
    else {
        panic!("not read")
    };
    assert_eq!((facts.tensors, facts.data_bytes), (2, 24));
    assert_eq!(facts.dtypes, ["BF16", "F32"]);
    for (case, header, data) in [
        (
            "past the data",
            r#"{"a":{"dtype":"F32","shape":[4],"data_offsets":[0,16]}}"#,
            8,
        ),
        (
            "a hole",
            r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[4,8]}}"#,
            8,
        ),
        (
            "an overlap",
            r#"{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]},"b":{"dtype":"F32","shape":[1],"data_offsets":[4,8]}}"#,
            8,
        ),
        (
            "bytes no tensor indexes",
            r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#,
            8,
        ),
        (
            "shape and offsets disagree",
            r#"{"a":{"dtype":"F32","shape":[3],"data_offsets":[0,8]}}"#,
            8,
        ),
        (
            "unknown dtype",
            r#"{"a":{"dtype":"Q4","shape":[1],"data_offsets":[0,1]}}"#,
            1,
        ),
        (
            "an extra member",
            r#"{"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1],"code":"x"}}"#,
            1,
        ),
        (
            "metadata not strings",
            r#"{"__metadata__":{"x":1},"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}"#,
            1,
        ),
        (
            "a duplicate key",
            r#"{"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}"#,
            1,
        ),
        ("not JSON", "{not json", 0),
        (
            "a shape that overflows",
            r#"{"a":{"dtype":"F64","shape":[9007199254740991,9007199254740991],"data_offsets":[0,8]}}"#,
            8,
        ),
    ] {
        let why = format::identify(&s.file("m.safetensors", &safetensors(header, data)));
        assert!(why.is_err(), "{case}");
    }
    // A header length past the file, or past the format's bound.
    let mut long = u64::MAX.to_le_bytes().to_vec();
    long.extend_from_slice(b"{}");
    assert!(format::identify(&s.file("m.safetensors", &long)).is_err());
    assert!(format::identify(&s.file("m.safetensors", b"\x01")).is_err());
}

#[test]
fn an_index_names_only_plain_shards_and_companions_are_data() {
    let s = Scratch::new("index");
    let ok = r#"{"metadata":{"total_size":2},"weight_map":{"a":"model-00001-of-00002.safetensors","b":"model-00002-of-00002.safetensors"}}"#;
    let Ok(Format::SafetensorsIndex(shards)) =
        format::identify(&s.file("model.safetensors.index.json", ok.as_bytes()))
    else {
        panic!()
    };
    assert_eq!(
        shards,
        [
            "model-00001-of-00002.safetensors",
            "model-00002-of-00002.safetensors"
        ]
    );
    for bad in [
        "../evil.safetensors",
        "/etc/passwd",
        "sub/x.safetensors",
        "x.py",
        ".hidden.safetensors",
    ] {
        let text = format!(r#"{{"weight_map":{{"a":"{bad}"}}}}"#);
        assert!(
            format::identify(&s.file("model.safetensors.index.json", text.as_bytes())).is_err(),
            "{bad}"
        );
    }
    assert_eq!(
        format::identify(&s.file("config.json", b"{\"a\":1}")),
        Ok(Format::JsonData)
    );
    assert!(format::identify(&s.file("config.json", b"{\"a\":")).is_err());
    assert_eq!(
        format::identify(&s.file("tokenizer.model", b"\x0a\x01")),
        Ok(Format::TokenizerModel)
    );
}

// ---- the library --------------------------------------------------------------

#[test]
fn an_import_keeps_exactly_the_bytes_it_hashed_and_verifies_them_again() {
    let s = Scratch::new("import");
    let lib = s.library();
    let weights = s.file("tiny-Q4_K_M.gguf", &llama(15, vec![]));
    let config = s.file("config.json", b"{\"x\":1}");
    let m = lib
        .import("tiny-q4", &[weights.clone(), config], None)
        .unwrap();
    assert_eq!(m.format, "GGUF");
    assert_eq!(m.quantization.as_deref(), Some("Q4_K_M"));
    assert_eq!(m.files.len(), 2);
    assert_eq!(lib.list().unwrap(), vec![m.clone()]);
    for (_, state) in lib.verify("tiny-q4").unwrap() {
        assert_eq!(state, FileState::Verified);
    }
    // The manifest says what is not proved: a local digest, no publisher,
    // never ready for inference.
    let text = fs::read_to_string(s.0.join("library/manifests/tiny-q4.json")).unwrap();
    assert!(
        text.contains("\"verified\":\"LOCAL_DIGEST_ONLY\""),
        "{text}"
    );
    assert!(text.contains("\"publisher_authenticated\":false"), "{text}");
    assert!(text.contains("\"ready_for_inference\":false"), "{text}");
    // Changing the source changes nothing kept.
    fs::write(&weights, b"changed").unwrap();
    for (_, state) in lib.verify("tiny-q4").unwrap() {
        assert_eq!(state, FileState::Verified);
    }
    // An installed model is never replaced.
    let again = s.file("other.gguf", &llama(7, vec![]));
    assert!(
        lib.import("tiny-q4", &[again], None)
            .unwrap_err()
            .contains("never replaced")
    );
    assert_eq!(lib.read("tiny-q4").unwrap(), m);
}

#[cfg(unix)]
#[test]
fn an_object_that_changed_is_corrupt_however_it_changed() {
    use std::os::unix::fs::PermissionsExt as _;
    let s = Scratch::new("corrupt");
    let lib = s.library();
    let m = lib
        .import("m", &[s.file("m.gguf", &llama(15, vec![]))], None)
        .unwrap();
    let object = s.0.join("library/objects/sha256").join(&m.files[0].sha256);
    let meta = fs::metadata(&object).unwrap();
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o444,
        "read-only, never executable"
    );
    let corrupt = |lib: &Library| match &lib.verify("m").unwrap()[0].1 {
        FileState::Corrupt(why) => why.clone(),
        FileState::Verified => panic!("verified"),
    };
    // Other bytes, the same length.
    fs::set_permissions(&object, fs::Permissions::from_mode(0o644)).unwrap();
    let mut bytes = fs::read(&object).unwrap();
    bytes[10] ^= 0xff;
    fs::write(&object, &bytes).unwrap();
    assert!(corrupt(&lib).contains("sha256"));
    // Executable.
    bytes[10] ^= 0xff;
    fs::write(&object, &bytes).unwrap();
    fs::set_permissions(&object, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(corrupt(&lib), "executable");
    // A symlink in its place.
    fs::remove_file(&object).unwrap();
    std::os::unix::fs::symlink(s.0.join("m.gguf"), &object).unwrap();
    assert_eq!(corrupt(&lib), "not a regular file");
    // Gone.
    fs::remove_file(&object).unwrap();
    assert_eq!(corrupt(&lib), "absent");
}

#[test]
fn a_split_or_sharded_model_is_imported_whole_or_not_at_all() {
    let s = Scratch::new("parts");
    let lib = s.library();
    let part = |no: u32, count: u32| {
        llama(
            15,
            vec![("split.no", Kv::U32(no)), ("split.count", Kv::U32(count))],
        )
    };
    let p1 = s.file("m-00001-of-00003.gguf", &part(0, 3));
    let p2 = s.file("m-00002-of-00003.gguf", &part(1, 3));
    let p3 = s.file("m-00003-of-00003.gguf", &part(2, 3));
    let why = lib
        .import("split", &[p1.clone(), p3.clone()], None)
        .unwrap_err();
    assert!(why.contains("part 2 of 3 is missing"), "{why}");
    assert!(
        s.objects().is_empty(),
        "nothing of a refused import is kept"
    );
    assert!(
        lib.import("split", &[p1.clone(), p2.clone(), p3.clone()], None)
            .is_ok()
    );
    // Shards with their index: every shard the index names.
    let shard = |n: u32| {
        let header = r#"{"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}"#;
        s.file(
            &format!("model-0000{n}-of-00002.safetensors"),
            &safetensors(header, 1),
        )
    };
    let index = s.file(
        "model.safetensors.index.json",
        br#"{"weight_map":{"a":"model-00001-of-00002.safetensors","b":"model-00002-of-00002.safetensors"}}"#,
    );
    let (s1, s2) = (shard(1), shard(2));
    let why = lib
        .import("sharded", &[index.clone(), s1.clone()], None)
        .unwrap_err();
    assert!(why.contains("missing"), "{why}");
    let m = lib.import("sharded", &[index, s1, s2], None).unwrap();
    assert_eq!(m.format, "SAFETENSORS");
    // GGUF and safetensors weights in one model, or two unrelated GGUF files.
    let a = s.file("a.gguf", &llama(15, vec![]));
    let b = s.file("b.gguf", &llama(7, vec![]));
    assert!(lib.import("mixed", &[a.clone(), b], None).is_err());
    assert!(lib.import("mixed", &[a, shard(1)], None).is_err());
}

#[test]
fn a_refused_file_refuses_its_model_and_leaves_nothing() {
    let s = Scratch::new("refused");
    let lib = s.library();
    let weights = s.file("m.gguf", &llama(15, vec![]));
    let pickle = s.file("pytorch_model.bin", b"\x80\x04\x95\x00");
    let why = lib
        .import("m", &[weights.clone(), pickle], None)
        .unwrap_err();
    assert!(why.contains("pickle"), "{why}");
    assert!(s.objects().is_empty());
    assert!(lib.list().unwrap().is_empty());
    // Not a model name, a path, a quota passed, nothing at all.
    for name in ["../m", "M", "a/b", "", ".m", &"m".repeat(65)] {
        assert!(
            lib.import(name, std::slice::from_ref(&weights), None)
                .is_err(),
            "{name:?}"
        );
    }
    assert!(
        lib.import("m", std::slice::from_ref(&weights), Some(10))
            .unwrap_err()
            .contains("quota")
    );
    assert!(lib.import("m", &[], None).is_err());
    assert!(
        lib.import("m", &[weights.clone(), weights], None)
            .unwrap_err()
            .contains("twice")
    );
}

/// SR-04: the file imported is the file checked, and exactly its length. A
/// source that grows after its check -- past the quota judged on its old
/// length -- is refused and leaves nothing at the target.
#[test]
fn a_source_that_changes_after_its_check_is_refused_and_leaves_nothing() {
    let s = Scratch::new("changed");
    let source = s.file("m.gguf", b"GGUF0123");
    let checked = fs::symlink_metadata(&source).unwrap();
    let kept = s.0.join("kept");
    let (digest, length) = copy_hashing(&source, &kept, &checked).unwrap();
    assert_eq!(length, 8);
    assert_eq!(digest.len(), 64);
    fs::write(&source, b"GGUF0123 and more after the check").unwrap();
    let grown = s.0.join("grown");
    let refused = copy_hashing(&source, &grown, &checked).unwrap_err();
    assert!(
        refused.contains("changed while it was imported"),
        "{refused}"
    );
    assert!(fs::symlink_metadata(&grown).is_err(), "nothing kept");
    // It shrinks after the check: refused too, and nothing is kept.
    let shrinking = s.file("s.gguf", b"GGUF0123GGUF4567");
    let before = fs::symlink_metadata(&shrinking).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&shrinking)
        .unwrap()
        .set_len(4)
        .unwrap();
    let shrunk = s.0.join("shrunk");
    let refused = copy_hashing(&shrinking, &shrunk, &before).unwrap_err();
    assert!(
        refused.contains("changed while it was imported"),
        "{refused}"
    );
    assert!(fs::symlink_metadata(&shrunk).is_err(), "nothing kept");
}

/// ISR2-02: the copy is bound to the checked length while it reads, not only
/// once it ends. A source extended after its check -- sparse, so extending it
/// costs nothing -- is refused, and the partial copy, watched while it is
/// made, never passes the checked length. Without the bound in the loop the
/// copy writes the whole extension before the check after it refuses, and a
/// source appended to without end never reaches that check.
#[cfg(unix)]
#[test]
fn a_source_extended_after_its_check_is_never_copied_past_its_checked_length() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    const CHECKED: u64 = 1 << 20;
    let s = Scratch::new("extended");
    let source = s.file("m.gguf", &vec![7u8; 1 << 20]);
    let checked = fs::symlink_metadata(&source).unwrap();
    assert_eq!(checked.len(), CHECKED);
    fs::OpenOptions::new()
        .write(true)
        .open(&source)
        .unwrap()
        .set_len(CHECKED + (64 << 20))
        .unwrap();
    let target = s.0.join("target");
    let done = Arc::new(AtomicBool::new(false));
    let peak = Arc::new(AtomicU64::new(0));
    let watcher = {
        let (target, done, peak) = (target.clone(), Arc::clone(&done), Arc::clone(&peak));
        std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                if let Ok(partial) = fs::metadata(&target) {
                    peak.fetch_max(partial.len(), Ordering::SeqCst);
                }
                std::thread::yield_now();
            }
        })
    };
    let copied = copy_hashing(&source, &target, &checked);
    done.store(true, Ordering::SeqCst);
    watcher.join().unwrap();
    let refused = copied.unwrap_err();
    assert!(
        refused.contains("changed while it was imported"),
        "{refused}"
    );
    assert!(fs::symlink_metadata(&target).is_err(), "nothing kept");
    let peak = peak.load(Ordering::SeqCst);
    assert!(
        peak <= CHECKED,
        "the partial copy reached {peak} bytes, past the checked {CHECKED}"
    );
}

/// ISR2-02, through the whole import: a model's weights, its second file,
/// extended (sparse, 64 MiB) between the import's checks and its copies --
/// the window, entered by the test-only hook there -- refuse the import, and
/// nothing of it is published: no manifest, not the object its first, intact
/// file made, and nothing left in the library's `tmp/`. The same library then
/// imports the same files unchanged, so the refusal was the growth's.
#[cfg(unix)]
#[test]
fn an_import_whose_source_grows_after_its_check_publishes_nothing() {
    let s = Scratch::new("import-grown");
    let config = s.file("config.json", b"{\"grown\":true}");
    let weights = s.file("m.gguf", &llama(15, vec![]));
    let checked = fs::metadata(&weights).unwrap().len();
    let lib = s.library();
    AFTER_CHECK.with(|hook| {
        hook.set(Some(|files: &[PathBuf]| {
            let last = files.last().unwrap();
            let len = fs::metadata(last).unwrap().len();
            fs::OpenOptions::new()
                .write(true)
                .open(last)
                .unwrap()
                .set_len(len + (64 << 20))
                .unwrap();
        }));
    });
    let refused = lib
        .import("grown", &[config.clone(), weights.clone()], None)
        .unwrap_err();
    assert!(
        refused.contains("changed while it was imported"),
        "{refused}"
    );
    assert!(
        AFTER_CHECK.with(std::cell::Cell::take).is_none(),
        "the hook ran"
    );
    assert!(lib.read("grown").is_err(), "no manifest");
    assert!(lib.list().unwrap().is_empty(), "no manifest");
    assert!(s.objects().is_empty(), "no object: {:?}", s.objects());
    let tmp: Vec<_> = fs::read_dir(s.0.join("library/tmp")).unwrap().collect();
    assert!(tmp.is_empty(), "nothing left in tmp: {tmp:?}");
    // The same files, the extension undone: imported, so nothing above was
    // the library refusing them for any other reason.
    fs::OpenOptions::new()
        .write(true)
        .open(&weights)
        .unwrap()
        .set_len(checked)
        .unwrap();
    let manifest = lib.import("grown", &[config, weights], None).unwrap();
    assert_eq!(manifest.name, "grown");
    assert_eq!(s.objects().len(), 2);
}

/// SR-04: a source swapped for a symlink after its check is not followed.
#[cfg(unix)]
#[test]
fn a_source_swapped_for_a_symlink_after_its_check_is_refused() {
    let s = Scratch::new("swapped");
    let source = s.file("m.gguf", b"GGUF0123");
    let checked = fs::symlink_metadata(&source).unwrap();
    let elsewhere = s.file("elsewhere.gguf", b"GGUF4567");
    fs::remove_file(&source).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &source).unwrap();
    let target = s.0.join("target");
    let refused = copy_hashing(&source, &target, &checked).unwrap_err();
    assert!(
        refused.contains("changed while it was imported"),
        "{refused}"
    );
    assert!(fs::symlink_metadata(&target).is_err(), "nothing kept");
}

#[cfg(unix)]
#[test]
fn a_symlink_is_never_followed_into_the_library_or_out_of_it() {
    let s = Scratch::new("symlink");
    let weights = s.file("m.gguf", &llama(15, vec![]));
    let link = s.0.join("link.gguf");
    std::os::unix::fs::symlink(&weights, &link).unwrap();
    let lib = s.library();
    assert!(
        lib.import("m", &[link], None)
            .unwrap_err()
            .contains("symlink")
    );
    let elsewhere = s.0.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    let root = s.0.join("linked-library");
    std::os::unix::fs::symlink(&elsewhere, &root).unwrap();
    assert!(Library::open(&root).is_err());
    assert!(Library::open(Path::new("relative/library")).is_err());
}

#[test]
fn removing_a_model_deletes_only_what_no_other_model_names() {
    let s = Scratch::new("remove");
    let lib = s.library();
    let shared = s.file("config.json", b"{\"shared\":true}");
    let a = s.file("a.gguf", &llama(15, vec![]));
    let b = s.file("b.gguf", &llama(7, vec![]));
    lib.import("a", &[a, shared.clone()], None).unwrap();
    lib.import("b", &[b, shared], None).unwrap();
    assert_eq!(s.objects().len(), 3);
    assert_eq!(
        lib.remove("a").unwrap(),
        1,
        "the config b still names stays"
    );
    assert_eq!(s.objects().len(), 2);
    assert!(lib.read("a").is_err());
    assert_eq!(lib.remove("b").unwrap(), 2);
    assert!(s.objects().is_empty());
    assert!(lib.remove("b").is_err());
    // An unrelated file beside the objects is never touched.
    let outside = s.file("keep.txt", b"keep");
    assert!(outside.exists());
}

#[test]
fn one_operation_at_a_time_and_an_interrupted_one_leaves_nothing_kept() {
    let s = Scratch::new("lock");
    let lib = s.library();
    let weights = s.file("m.gguf", &llama(15, vec![]));
    fs::write(s.0.join("library/lock"), b"1").unwrap();
    assert!(
        lib.import("m", std::slice::from_ref(&weights), None)
            .unwrap_err()
            .contains("another operation")
    );
    fs::remove_file(s.0.join("library/lock")).unwrap();
    // What a killed import left in tmp is swept by the next one.
    fs::write(s.0.join("library/tmp/import-dead"), b"partial").unwrap();
    lib.import("m", &[weights], None).unwrap();
    assert_eq!(fs::read_dir(s.0.join("library/tmp")).unwrap().count(), 0);
    assert!(!s.0.join("library/lock").exists(), "released");
    // A tampered manifest is not read as one.
    fs::write(s.0.join("library/manifests/m.json"), b"{\"schema\":\"x\"}").unwrap();
    assert!(lib.read("m").is_err());
    assert!(is_model_name("qwen2.5-7b-q4_k_m"));
}

#[test]
fn what_a_file_or_a_manifest_says_cannot_drive_a_terminal_or_rewrite_json() {
    // A GGUF whose metadata carries terminal control sequences: read as
    // data, shown escaped.
    let s = Scratch::new("hostile-text");
    let path = s.file(
        "m.gguf",
        &gguf(
            3,
            &[
                ("general.architecture", Kv::Str("llama")),
                ("general.name", Kv::Str("x\u{1b}[2J\u{1b}]0;owned\u{7}")),
                ("general.license", Kv::Str("mit\r\nfake: line\u{202e}")),
            ],
        ),
    );
    let Ok(Format::Gguf(g)) = format::identify(&path) else {
        panic!()
    };
    for text in [g.name.unwrap(), g.license.unwrap()] {
        let said = shown(&text);
        assert!(
            said.chars().all(|c| c == ' ' || c.is_ascii_graphic()),
            "{said:?}"
        );
        assert!(!said.contains('\u{1b}') && !said.contains('\n'), "{said:?}");
    }
    assert_eq!(shown("Q4_K_M apache-2.0"), "Q4_K_M apache-2.0");
    // A tampered manifest's text stays inside its JSON string.
    let mut m = manifest("GGUF", 1, false);
    m.quantization = Some("Q4\",\"ready_for_inference\":true,\"x\":\"".to_owned());
    let line = json_line(&m);
    let Ok(dwk_proto::json::Value::Object(o)) =
        dwk_proto::json::parse(line.as_bytes(), dwk_proto::json::ParseOptions::dwkp())
    else {
        panic!("not JSON: {line}")
    };
    assert_eq!(
        o.get("ready_for_inference"),
        Some(&dwk_proto::json::Value::Bool(false))
    );
    assert!(o.get("x").is_none());
    // A manifest naming a format this build does not read is not one.
    let lib = s.library();
    lib.import("m", &[s.file("n.gguf", &llama(15, vec![]))], None)
        .unwrap();
    let path = s.0.join("library/manifests/m.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o644));
    }
    let text = fs::read_to_string(&path).unwrap();
    let tampered = text.replace("\"format\":\"GGUF\"", "\"format\":\"PICKLE\"");
    assert_ne!(tampered, text);
    fs::write(&path, tampered).unwrap();
    assert!(lib.read("m").is_err());
}

// ---- estimates --------------------------------------------------------------------

fn manifest(format: &str, weights: u64, facts: bool) -> Manifest {
    Manifest {
        name: "m".to_owned(),
        files: vec![super::library::Entry {
            file: "m".to_owned(),
            sha256: "0".repeat(64),
            bytes: weights,
            format: format.to_owned(),
        }],
        format: format.to_owned(),
        quantization: None,
        architecture: None,
        context_length: facts.then_some(8192),
        block_count: facts.then_some(32),
        embedding_length: facts.then_some(4096),
        head_count: facts.then_some(32),
        head_count_kv: facts.then_some(8),
        license: None,
    }
}

fn host(ram: Option<u64>, vram: Option<u64>) -> Facts {
    Facts {
        arch: "x86_64",
        os: "linux",
        threads: Some(8),
        ram_total: ram,
        ram_available: ram,
        vram,
    }
}

#[test]
fn an_estimate_is_explained_and_never_promised_from_a_size() {
    const GIB: u64 = 1 << 30;
    // 4 GiB of weights; KV at 4096 tokens: 2 x 32 x 4096 x 1024 x 2 = 512 MiB;
    // overhead 0.4 GiB + 512 MiB: about 5.3 GiB in all.
    let m = manifest("GGUF", 4 * GIB, true);
    for (ram, fit) in [
        (16 * GIB, Headroom::Fits),
        (13 * (GIB >> 1), Headroom::LikelyFits),
        (5 * GIB, Headroom::MayNotFit),
        (2 * GIB, Headroom::DoesNotFit),
    ] {
        let e = hardware::estimate(&m, 4096, &host(Some(ram), None));
        assert_eq!(e.fit, fit, "{ram}: {}", e.why);
        assert_eq!(e.place, "RAM");
        assert!(e.why.contains("key-value cache"), "{}", e.why);
    }
    // The operator's stated graphics memory is the budget, and named so.
    let e = hardware::estimate(&m, 4096, &host(Some(GIB), Some(24 * GIB)));
    assert_eq!((e.fit, e.place), (Headroom::Fits, "GPU"));
    // Memory unknown: UNKNOWN, on every platform this build cannot read.
    for os in ["windows", "macos", "linux"] {
        let mut facts = host(None, None);
        facts.os = os;
        assert_eq!(
            hardware::estimate(&m, 4096, &facts).fit,
            Headroom::Unknown,
            "{os}"
        );
    }
    // No layer and width facts: no promise, unless the weights alone exceed.
    let bare = manifest("GGUF", 4 * GIB, false);
    assert_eq!(
        hardware::estimate(&bare, 4096, &host(Some(64 * GIB), None)).fit,
        Headroom::Unknown
    );
    assert_eq!(
        hardware::estimate(&bare, 4096, &host(Some(GIB), None)).fit,
        Headroom::DoesNotFit
    );
    // Safetensors: no backend in this build, so no runtime size.
    let st = manifest("SAFETENSORS", 4 * GIB, true);
    let e = hardware::estimate(&st, 4096, &host(Some(64 * GIB), None));
    assert_eq!(e.fit, Headroom::Unknown);
    assert!(e.why.contains("no local backend"), "{}", e.why);
    // The context asked for is bounded by the model's own.
    let small = hardware::estimate(&m, 1 << 30, &host(Some(16 * GIB), None));
    assert!(small.why.contains("at 8192 tokens"), "{}", small.why);
    assert_eq!(
        small.needed,
        hardware::estimate(&m, 8192, &host(Some(16 * GIB), None)).needed
    );
}

#[test]
fn meminfo_is_read_as_the_kernel_writes_it() {
    let text = "MemTotal:       32768000 kB\nMemFree:  100 kB\nMemAvailable:   16384000 kB\n";
    assert_eq!(
        hardware::meminfo(text),
        (Some(32_768_000 * 1024), Some(16_384_000 * 1024))
    );
    assert_eq!(hardware::meminfo("garbage"), (None, None));
    assert_eq!(hardware::meminfo("MemTotal: lots kB\n"), (None, None));
}

// ---- the command line -------------------------------------------------------------

#[test]
fn the_commands_are_exactly_the_offline_ones() {
    assert_eq!(run(&[]), 0);
    assert_eq!(run(&["--help"]), 0);
    assert_eq!(run(&["status"]), 0);
    // A library is named, never guessed.
    assert_eq!(run(&["list"]), EXIT_REFUSED);
    assert_eq!(run(&["import", "--name", "m", "x.gguf"]), EXIT_REFUSED);
    assert_eq!(run(&["list", "--library"]), EXIT_USAGE);
    assert_eq!(run(&["list", "--frob"]), EXIT_USAGE);
    // Nothing that would need the network, or inference, exists.
    for absent in [
        "search",
        "info",
        "variants",
        "pull",
        "pause",
        "resume",
        "cancel",
        "jobs",
        "use",
        "providers",
        "download",
    ] {
        assert_eq!(
            run(&[absent]),
            EXIT_USAGE,
            "`direwolf models {absent}` must not exist"
        );
    }
}

//! What a model file is, read without running anything in it (ADR-0072,
//! Proposed).
//!
//! Every reader here is **bounded and non-executing**: it reads a header the
//! format defines, checks it against the file's own length, and keeps a few
//! facts. Nothing is loaded into an inference engine to learn what it is, no
//! archive is extracted, and no code a repository ships is run. A pickle --
//! executable on load by design -- and a zip archive (a PyTorch checkpoint is
//! a pickle inside one) are refused by their bytes, whatever their names say.
//!
//! Formats: GGUF (one file, or the parts of a split one); safetensors (one
//! file, or the shards an index names); and the data-only companions a model
//! needs -- JSON configuration and tokenizer files, and `tokenizer.model`.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use dwk_proto::json::{Number, ParseOptions, Value, parse};

/// The most GGUF metadata read: every key and value, tokenizer
/// vocabularies included, before the tensor table.
const MAX_GGUF_METADATA_BYTES: u64 = 256 * 1024 * 1024;
/// The most GGUF metadata keys.
const MAX_GGUF_KEYS: u64 = 65_536;
/// The longest GGUF string.
const MAX_GGUF_STRING: u64 = 1 << 20;
/// The most elements of one GGUF array.
const MAX_GGUF_ARRAY: u64 = 1 << 24;
/// The most parts a split GGUF file may have.
const MAX_GGUF_PARTS: u64 = 4096;
/// The largest safetensors header (the format's own bound).
const MAX_SAFETENSORS_HEADER: u64 = 100 * 1024 * 1024;
/// The largest JSON companion or index.
const MAX_JSON_BYTES: u64 = 16 * 1024 * 1024;
/// The largest `tokenizer.model`.
const MAX_TOKENIZER_MODEL: u64 = 64 * 1024 * 1024;

/// What a file was found to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Format {
    /// A GGUF file, or one part of a split one.
    Gguf(GgufFacts),
    /// A safetensors file, or one shard.
    Safetensors(SafetensorsFacts),
    /// A safetensors index: the shard file names its weight map names.
    SafetensorsIndex(Vec<String>),
    /// A JSON configuration or tokenizer file: data, parsed and bounded.
    JsonData,
    /// A `tokenizer.model`: opaque data, bounded.
    TokenizerModel,
}

impl Format {
    /// The word a manifest and the CLI use.
    pub(crate) const fn word(&self) -> &'static str {
        match self {
            Self::Gguf(_) => "GGUF",
            Self::Safetensors(_) => "SAFETENSORS",
            Self::SafetensorsIndex(_) => "SAFETENSORS_INDEX",
            Self::JsonData => "JSON",
            Self::TokenizerModel => "TOKENIZER_MODEL",
        }
    }
}

/// The facts a GGUF header gives, read from its metadata alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GgufFacts {
    pub(crate) version: u32,
    pub(crate) tensors: u64,
    pub(crate) architecture: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) license: Option<String>,
    /// `general.file_type`: llama.cpp's quantisation of the weights.
    pub(crate) file_type: Option<u64>,
    pub(crate) context_length: Option<u64>,
    pub(crate) block_count: Option<u64>,
    pub(crate) embedding_length: Option<u64>,
    pub(crate) head_count: Option<u64>,
    pub(crate) head_count_kv: Option<u64>,
    /// `split.no` and `split.count`, for one part of a split file.
    pub(crate) split: Option<(u64, u64)>,
}

impl GgufFacts {
    /// The quantisation `general.file_type` names -- the file's own claim,
    /// never its name's; `None` when the file does not say.
    pub(crate) fn quantization(&self) -> Option<String> {
        let name = match self.file_type? {
            0 => "F32",
            1 => "F16",
            2 => "Q4_0",
            3 => "Q4_1",
            7 => "Q8_0",
            8 => "Q5_0",
            9 => "Q5_1",
            10 => "Q2_K",
            11 => "Q3_K_S",
            12 => "Q3_K_M",
            13 => "Q3_K_L",
            14 => "Q4_K_S",
            15 => "Q4_K_M",
            16 => "Q5_K_S",
            17 => "Q5_K_M",
            18 => "Q6_K",
            32 => "BF16",
            other => return Some(format!("FILE_TYPE_{other}")),
        };
        Some(name.to_owned())
    }
}

/// The facts a safetensors header gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SafetensorsFacts {
    pub(crate) tensors: u64,
    /// Every dtype named, sorted, once.
    pub(crate) dtypes: Vec<String>,
    /// The bytes after the header, every one indexed by exactly one tensor.
    pub(crate) data_bytes: u64,
}

/// Identify `path`, reading only what its format defines; or why it is not
/// a file this build imports.
pub(crate) fn identify(path: &Path) -> Result<Format, String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("a file name that is not UTF-8")?;
    let file = File::open(path).map_err(|e| format!("cannot open: {e}"))?;
    let length = file
        .metadata()
        .map_err(|e| format!("cannot read its size: {e}"))?
        .len();
    let mut head = [0u8; 8];
    let got = read_up_to(&file, &mut head)?;
    let head = head.get(..got).unwrap_or_default();
    // The safetensors header's first eight bytes are a little-endian length,
    // which can look like anything; the name decides, and the header proves.
    if name.ends_with(".safetensors") {
        return safetensors(path, length).map(Format::Safetensors);
    }
    if head.starts_with(b"GGUF") {
        return gguf(path).map(Format::Gguf);
    }
    if let [0x80, version, ..] = head
        && (2..=5).contains(version)
    {
        return Err("a pickle: it runs code when it is loaded, and is never imported".to_owned());
    }
    if head.starts_with(b"PK\x03\x04") {
        return Err(
            "a zip archive (a PyTorch checkpoint is a pickle inside one): never extracted or \
             imported"
                .to_owned(),
        );
    }
    if name.ends_with(".gguf") {
        return Err("named .gguf without the GGUF magic".to_owned());
    }
    if name.ends_with(".safetensors.index.json") {
        return index(path, length).map(Format::SafetensorsIndex);
    }
    if name.ends_with(".json") {
        json_file(path, length)?;
        return Ok(Format::JsonData);
    }
    if name == "tokenizer.model" {
        if length > MAX_TOKENIZER_MODEL {
            return Err(format!("larger than {MAX_TOKENIZER_MODEL} bytes"));
        }
        return Ok(Format::TokenizerModel);
    }
    Err(
        "not a format this build imports: GGUF, safetensors (and its index), JSON metadata, \
         tokenizer.model"
            .to_owned(),
    )
}

fn read_up_to(mut file: &File, buffer: &mut [u8]) -> Result<usize, String> {
    let mut filled = 0;
    while let Some(rest) = buffer.get_mut(filled..) {
        if rest.is_empty() {
            break;
        }
        match file.read(rest) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("cannot read: {e}")),
        }
    }
    Ok(filled)
}

// ---- GGUF -------------------------------------------------------------------

/// A bounded reader over a GGUF file's header and metadata.
struct Gguf<R> {
    from: R,
}

impl<R: Read> Gguf<R> {
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let mut out = [0u8; N];
        self.from
            .read_exact(&mut out)
            .map_err(|_| "the metadata is cut short, or past its bound".to_owned())?;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.fixed::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.fixed::<8>()?))
    }

    fn skip(&mut self, count: u64) -> Result<(), String> {
        let skipped = io::copy(&mut (&mut self.from).take(count), &mut io::sink())
            .map_err(|_| "the metadata cannot be read".to_owned())?;
        if skipped == count {
            Ok(())
        } else {
            Err("the metadata is cut short, or past its bound".to_owned())
        }
    }

    fn string(&mut self) -> Result<String, String> {
        let length = self.u64()?;
        if length > MAX_GGUF_STRING {
            return Err("a metadata string past its bound".to_owned());
        }
        let length = usize::try_from(length).map_err(|_| "a string too long".to_owned())?;
        let mut bytes = vec![0u8; length];
        self.from
            .read_exact(&mut bytes)
            .map_err(|_| "the metadata is cut short, or past its bound".to_owned())?;
        String::from_utf8(bytes).map_err(|_| "a metadata string that is not UTF-8".to_owned())
    }

    fn skip_string(&mut self) -> Result<(), String> {
        let length = self.u64()?;
        if length > MAX_GGUF_STRING {
            return Err("a metadata string past its bound".to_owned());
        }
        self.skip(length)
    }

    /// One value of type `kind`: an unsigned integer or a string kept, every
    /// other value read past.
    fn value(&mut self, kind: u32) -> Result<Kept, String> {
        Ok(match kind {
            0 => Kept::Unsigned(u64::from(self.fixed::<1>()?.first().copied().unwrap_or(0))),
            2 => Kept::Unsigned(u64::from(u16::from_le_bytes(self.fixed::<2>()?))),
            4 => Kept::Unsigned(u64::from(self.u32()?)),
            10 => Kept::Unsigned(self.u64()?),
            1 | 7 => {
                self.skip(1)?;
                Kept::Nothing
            }
            3 => {
                self.skip(2)?;
                Kept::Nothing
            }
            5 | 6 => {
                self.skip(4)?;
                Kept::Nothing
            }
            11 | 12 => {
                self.skip(8)?;
                Kept::Nothing
            }
            8 => Kept::Text(self.string()?),
            9 => {
                self.array()?;
                Kept::Nothing
            }
            other => return Err(format!("a metadata value of unknown type {other}")),
        })
    }

    /// An array, read past without keeping its elements.
    fn array(&mut self) -> Result<(), String> {
        let kind = self.u32()?;
        let count = self.u64()?;
        if count > MAX_GGUF_ARRAY {
            return Err("a metadata array past its bound".to_owned());
        }
        let width: u64 = match kind {
            0 | 1 | 7 => 1,
            2 | 3 => 2,
            4..=6 => 4,
            10..=12 => 8,
            8 => {
                for _ in 0..count {
                    self.skip_string()?;
                }
                return Ok(());
            }
            9 => return Err("an array of arrays: not a shape this reader takes".to_owned()),
            other => return Err(format!("an array of unknown type {other}")),
        };
        self.skip(
            count
                .checked_mul(width)
                .ok_or("an array whose size overflows")?,
        )
    }
}

/// What a metadata value was read as.
enum Kept {
    Unsigned(u64),
    Text(String),
    Nothing,
}

fn gguf(path: &Path) -> Result<GgufFacts, String> {
    let file = File::open(path).map_err(|e| format!("cannot open: {e}"))?;
    let mut r = Gguf {
        from: io::BufReader::new(file).take(MAX_GGUF_METADATA_BYTES),
    };
    if &r.fixed::<4>()? != b"GGUF" {
        return Err("not GGUF".to_owned());
    }
    let mut facts = GgufFacts {
        version: r.u32()?,
        ..GgufFacts::default()
    };
    if !(2..=3).contains(&facts.version) {
        return Err(format!("GGUF version {} is not 2 or 3", facts.version));
    }
    facts.tensors = r.u64()?;
    let keys = r.u64()?;
    if keys > MAX_GGUF_KEYS {
        return Err("more metadata keys than this reader takes".to_owned());
    }
    let (mut split_no, mut split_count) = (None, None);
    let mut numbers: Vec<(String, u64)> = Vec::new();
    for _ in 0..keys {
        let key = r.string()?;
        let kind = r.u32()?;
        match (key.as_str(), r.value(kind)?) {
            ("general.architecture", Kept::Text(text)) => facts.architecture = Some(text),
            ("general.name", Kept::Text(text)) => facts.name = Some(text),
            ("general.license", Kept::Text(text)) => facts.license = Some(text),
            ("general.file_type", Kept::Unsigned(n)) => facts.file_type = Some(n),
            ("split.no", Kept::Unsigned(n)) => split_no = Some(n),
            ("split.count", Kept::Unsigned(n)) => split_count = Some(n),
            (_, Kept::Unsigned(n)) => numbers.push((key, n)),
            _ => {}
        }
    }
    if let Some(arch) = &facts.architecture {
        let find = |suffix: &str| {
            let wanted = format!("{arch}.{suffix}");
            numbers.iter().find(|(k, _)| *k == wanted).map(|(_, v)| *v)
        };
        facts.context_length = find("context_length");
        facts.block_count = find("block_count");
        facts.embedding_length = find("embedding_length");
        facts.head_count = find("attention.head_count");
        facts.head_count_kv = find("attention.head_count_kv");
    }
    facts.split = match (split_no, split_count) {
        (None, None) => None,
        (Some(no), Some(count)) if (1..=MAX_GGUF_PARTS).contains(&count) && no < count => {
            Some((no, count))
        }
        _ => return Err("split.no and split.count disagree".to_owned()),
    };
    Ok(facts)
}

// ---- safetensors and JSON -----------------------------------------------------

/// The size in bytes of one element of a safetensors dtype.
fn dtype_width(dtype: &str) -> Option<u64> {
    Some(match dtype {
        "BOOL" | "U8" | "I8" | "F8_E4M3" | "F8_E5M2" => 1,
        "U16" | "I16" | "F16" | "BF16" => 2,
        "U32" | "I32" | "F32" => 4,
        "U64" | "I64" | "F64" => 8,
        _ => return None,
    })
}

fn integer(value: &Value) -> Option<u64> {
    match value {
        Value::Number(Number::Int(n)) => u64::try_from(*n).ok(),
        _ => None,
    }
}

fn read_json(path: &Path, limit: u64) -> Result<Value, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| format!("cannot open: {e}"))?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read: {e}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(format!("larger than {limit} bytes"));
    }
    parse(&bytes, ParseOptions::dwkp()).map_err(|e| format!("not strict JSON: {e}"))
}

fn json_file(path: &Path, length: u64) -> Result<(), String> {
    if length > MAX_JSON_BYTES {
        return Err(format!("larger than {MAX_JSON_BYTES} bytes"));
    }
    read_json(path, MAX_JSON_BYTES).map(|_| ())
}

fn safetensors(path: &Path, length: u64) -> Result<SafetensorsFacts, String> {
    let mut file = File::open(path).map_err(|e| format!("cannot open: {e}"))?;
    let mut prefix = [0u8; 8];
    file.read_exact(&mut prefix)
        .map_err(|_| "shorter than a safetensors header".to_owned())?;
    let header = u64::from_le_bytes(prefix);
    let after = length
        .checked_sub(8)
        .ok_or("shorter than a safetensors header")?;
    if header > MAX_SAFETENSORS_HEADER || header > after {
        return Err("a safetensors header longer than its bound or its file".to_owned());
    }
    let size = usize::try_from(header).map_err(|_| "a header too long".to_owned())?;
    let mut bytes = vec![0u8; size];
    file.read_exact(&mut bytes)
        .map_err(|_| "a safetensors header cut short".to_owned())?;
    let Ok(Value::Object(document)) = parse(&bytes, ParseOptions::dwkp()) else {
        return Err("a safetensors header that is not one strict JSON object".to_owned());
    };
    let data = after
        .checked_sub(header)
        .ok_or("a header longer than its file")?;
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut dtypes: Vec<String> = Vec::new();
    for (name, entry) in document.iter() {
        if name == "__metadata__" {
            let Value::Object(metadata) = entry else {
                return Err("__metadata__ is not an object".to_owned());
            };
            if metadata.iter().any(|(_, v)| !matches!(v, Value::String(_))) {
                return Err("__metadata__ holds something other than strings".to_owned());
            }
            continue;
        }
        let Value::Object(tensor) = entry else {
            return Err(format!("tensor {name:?} is not an object"));
        };
        if tensor
            .iter()
            .any(|(k, _)| !matches!(k, "dtype" | "shape" | "data_offsets"))
        {
            return Err(format!(
                "tensor {name:?} has a member the format does not define"
            ));
        }
        let Some(Value::String(dtype)) = tensor.get("dtype") else {
            return Err(format!("tensor {name:?} has no dtype"));
        };
        let width =
            dtype_width(dtype).ok_or_else(|| format!("tensor {name:?}: dtype {dtype:?}"))?;
        let Some(Value::Array(shape)) = tensor.get("shape") else {
            return Err(format!("tensor {name:?} has no shape"));
        };
        let mut elements: u64 = 1;
        for dimension in shape {
            let dimension = integer(dimension).ok_or_else(|| format!("tensor {name:?}: shape"))?;
            elements = elements
                .checked_mul(dimension)
                .ok_or_else(|| format!("tensor {name:?}: a shape that overflows"))?;
        }
        let Some(Value::Array(offsets)) = tensor.get("data_offsets") else {
            return Err(format!("tensor {name:?} has no data_offsets"));
        };
        let [begin, end] = offsets.as_slice() else {
            return Err(format!("tensor {name:?}: data_offsets is not [begin, end]"));
        };
        let (begin, end) = integer(begin)
            .zip(integer(end))
            .filter(|(b, e)| b <= e && *e <= data)
            .ok_or_else(|| format!("tensor {name:?}: data_offsets outside the data"))?;
        let span = elements
            .checked_mul(width)
            .ok_or_else(|| format!("tensor {name:?}: a size that overflows"))?;
        if end.checked_sub(begin) != Some(span) {
            return Err(format!(
                "tensor {name:?}: its offsets do not hold its shape and dtype"
            ));
        }
        ranges.push((begin, end));
        if !dtypes.contains(dtype) {
            dtypes.push(dtype.clone());
        }
    }
    // Every data byte indexed by exactly one tensor: no hole, no overlap.
    ranges.sort_unstable();
    let mut at = 0u64;
    for (begin, end) in &ranges {
        if *begin != at {
            return Err("the tensors' data has a hole or an overlap".to_owned());
        }
        at = *end;
    }
    if at != data {
        return Err("the file holds bytes no tensor indexes".to_owned());
    }
    dtypes.sort();
    Ok(SafetensorsFacts {
        tensors: u64::try_from(ranges.len()).unwrap_or(u64::MAX),
        dtypes,
        data_bytes: data,
    })
}

/// Whether `name` is a plain file name: no directory, no `..`, no control
/// character, nothing a remote index could use to name a path elsewhere.
pub(crate) fn is_plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

fn index(path: &Path, length: u64) -> Result<Vec<String>, String> {
    if length > MAX_JSON_BYTES {
        return Err(format!("larger than {MAX_JSON_BYTES} bytes"));
    }
    let Value::Object(document) = read_json(path, MAX_JSON_BYTES)? else {
        return Err("an index that is not an object".to_owned());
    };
    let Some(Value::Object(map)) = document.get("weight_map") else {
        return Err("an index without a weight_map".to_owned());
    };
    let mut shards: Vec<String> = Vec::new();
    for (tensor, shard) in map.iter() {
        let Value::String(shard) = shard else {
            return Err(format!(
                "tensor {tensor:?} maps to something other than a file"
            ));
        };
        if !is_plain_name(shard) || !shard.ends_with(".safetensors") {
            return Err(format!(
                "tensor {tensor:?} maps to {shard:?}: not a plain .safetensors file name"
            ));
        }
        if !shards.contains(shard) {
            shards.push(shard.clone());
        }
    }
    if shards.is_empty() {
        return Err("an index naming no shard".to_owned());
    }
    shards.sort();
    Ok(shards)
}

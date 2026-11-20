//! `direwolf models` -- the operator's local model library (ADR-0072,
//! Proposed).
//!
//! # What exists
//!
//! An offline library an operator manages from this command line, and no
//! one else: import local model files (GGUF, single or split; safetensors,
//! single or sharded with its index; their JSON and tokenizer companions),
//! hash them, identify them by their own headers, list, verify again,
//! inspect, remove, and estimate what this host can hold. No daemon is
//! contacted and no DWKP operation exists for any of it, so no agent can
//! reach it.
//!
//! # What does not, and why
//!
//! Search, download, pause and resume, Hugging Face revisions, Ollama and
//! llama.cpp server profiles, and selecting a model for inference are **not
//! built**, and no command pretends otherwise. A download is egress: in
//! DireWolf the broker's HTTPS client is the only one (TX044), every
//! destination is the authority's decision (F-06, ADR-0071), and a download
//! needs a private-protocol operation that streams to the library -- which
//! does not exist. Inference is M7's.

mod format;
mod hardware;
mod library;

#[cfg(test)]
mod tests;

use std::path::PathBuf;

use dwk_proto::json::{Number, Object, Value, to_canonical_bytes};
use library::{FileState, Library, Manifest};

/// Exit code for a refusal or a failed verification.
const EXIT_REFUSED: u8 = 1;
/// Exit code for a usage error.
const EXIT_USAGE: u8 = 2;

/// The default context an estimate is made at.
const DEFAULT_CONTEXT: u64 = 4096;

const USAGE: &str = "\
direwolf models - the operator's local model library (offline)

USAGE:
    direwolf models status    [--library <DIR>]
    direwolf models inspect   <FILE>...
    direwolf models import    --library <DIR> --name <NAME> [--quota-bytes <N>] <FILE>...
    direwolf models list      --library <DIR> [--json]
    direwolf models verify    --library <DIR> <NAME>
    direwolf models remove    --library <DIR> <NAME>
    direwolf models recommend [--library <DIR>] [--context <TOKENS>] [--vram-gib <N>]

Formats: GGUF (single or split), safetensors (single, or shards with their
index), JSON configuration and tokenizer files, tokenizer.model. A pickle or
a zip checkpoint is refused by its bytes.

Not built (ADR-0072, Proposed): search, download, pause/resume, Hugging Face
and Ollama sources, llama.cpp server profiles, selecting a model for
inference. A download is egress, and egress is the authority's decision.
";

/// What the command line asked for.
struct Options {
    library: Option<PathBuf>,
    name: Option<String>,
    quota: Option<u64>,
    context: Option<u64>,
    vram_gib: Option<u64>,
    json: bool,
    rest: Vec<String>,
}

fn options(args: &[&str]) -> Result<Options, String> {
    let mut out = Options {
        library: None,
        name: None,
        quota: None,
        context: None,
        vram_gib: None,
        json: false,
        rest: Vec::new(),
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .map(|v| (*v).to_owned())
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        let number = |flag: &str, text: String| {
            text.parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| format!("{flag} takes a positive whole number"))
        };
        match *arg {
            "--library" => out.library = Some(PathBuf::from(value()?)),
            "--name" => out.name = Some(value()?),
            "--quota-bytes" => out.quota = Some(number(arg, value()?)?),
            "--context" => out.context = Some(number(arg, value()?)?),
            "--vram-gib" => out.vram_gib = Some(number(arg, value()?)?),
            "--json" => out.json = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag {flag}")),
            word => out.rest.push(word.to_owned()),
        }
    }
    Ok(out)
}

/// Text a model file or a manifest supplied, fit for a terminal: every
/// control character -- an escape sequence among them -- and every
/// character outside printable ASCII is written escaped, never sent raw.
pub(crate) fn shown(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            let raw = c == ' ' || c.is_ascii_graphic();
            let escaped: Vec<char> = if raw {
                vec![c]
            } else {
                c.escape_default().collect()
            };
            escaped
        })
        .collect()
}

/// One model as a line of JSON, built by the encoder: a manifest's text
/// cannot end a string or add a member.
pub(crate) fn json_line(m: &Manifest) -> String {
    let text = |t: Option<&String>| t.map_or(Value::Null, |s| Value::String(s.clone()));
    let count = |n: u64| i64::try_from(n).map_or(Value::Null, |n| Value::Number(Number::Int(n)));
    let mut o = Object::new();
    for (key, value) in [
        ("name", Value::String(m.name.clone())),
        ("format", Value::String(m.format.clone())),
        ("quantization", text(m.quantization.as_ref())),
        ("architecture", text(m.architecture.as_ref())),
        ("license", text(m.license.as_ref())),
        (
            "files",
            count(u64::try_from(m.files.len()).unwrap_or(u64::MAX)),
        ),
        ("weight_bytes", count(m.weight_bytes())),
        ("verified", Value::String("LOCAL_DIGEST_ONLY".to_owned())),
        ("ready_for_inference", Value::Bool(false)),
    ] {
        let _ = o.insert(key.to_owned(), value);
    }
    String::from_utf8_lossy(&to_canonical_bytes(&Value::Object(o))).into_owned()
}

fn library(o: &Options) -> Result<Library, String> {
    let root = o
        .library
        .as_deref()
        .ok_or("--library <DIR> is required: the library is named, never guessed")?;
    Library::open(root)
}

/// Run `direwolf models <args>`. Returns the exit code.
pub(crate) fn run(args: &[&str]) -> u8 {
    let Some((command, rest)) = args.split_first() else {
        print!("{USAGE}");
        return 0;
    };
    let o = match options(rest) {
        Ok(o) => o,
        Err(why) => {
            eprintln!("direwolf models: {why}");
            return EXIT_USAGE;
        }
    };
    let outcome = match *command {
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(0)
        }
        "status" => status(&o),
        "inspect" => inspect(&o),
        "import" => import(&o),
        "list" => list(&o),
        "verify" => verify(&o),
        "remove" => remove(&o),
        "recommend" => recommend(&o),
        other => {
            eprintln!("direwolf models: unknown command {other}");
            eprintln!("Try `direwolf models --help`.");
            return EXIT_USAGE;
        }
    };
    match outcome {
        Ok(code) => code,
        Err(why) => {
            eprintln!("direwolf models: {why}");
            EXIT_REFUSED
        }
    }
}

fn status(o: &Options) -> Result<u8, String> {
    match &o.library {
        Some(_) => {
            let models = library(o)?.list()?;
            println!("library: {} model(s)", models.len());
        }
        None => println!("library: none named (--library <DIR>)"),
    }
    println!("downloads: not built -- needs the authority's download path (ADR-0072, Proposed)");
    println!("sources: local files only; Hugging Face and Ollama are not built");
    println!("inference: not available -- M7 is not built; no model is ready for inference");
    Ok(0)
}

fn inspect(o: &Options) -> Result<u8, String> {
    if o.rest.is_empty() {
        return Err("inspect needs at least one file".to_owned());
    }
    let mut refused = false;
    for file in &o.rest {
        match format::identify(std::path::Path::new(file)) {
            Ok(format::Format::Gguf(g)) => {
                println!(
                    "{file}: GGUF v{} name={} tensors={} architecture={} quantization={} \
                     context={} split={} license={}",
                    g.version,
                    shown(g.name.as_deref().unwrap_or("-")),
                    g.tensors,
                    shown(g.architecture.as_deref().unwrap_or("-")),
                    g.quantization().as_deref().unwrap_or("-"),
                    g.context_length.map_or("-".to_owned(), |c| c.to_string()),
                    g.split.map_or("-".to_owned(), |(n, c)| format!(
                        "{}/{c}",
                        n.saturating_add(1)
                    )),
                    shown(g.license.as_deref().unwrap_or("not stated"))
                );
            }
            Ok(format::Format::Safetensors(s)) => println!(
                "{file}: SAFETENSORS tensors={} dtypes={} data_bytes={}",
                s.tensors,
                s.dtypes.join(","),
                s.data_bytes
            ),
            Ok(format::Format::SafetensorsIndex(shards)) => {
                println!("{file}: SAFETENSORS_INDEX shards={}", shards.join(","));
            }
            Ok(other) => println!("{file}: {}", other.word()),
            Err(why) => {
                refused = true;
                println!("{file}: REFUSED {why}");
            }
        }
    }
    Ok(if refused { EXIT_REFUSED } else { 0 })
}

fn import(o: &Options) -> Result<u8, String> {
    let name = o.name.as_deref().ok_or("--name <NAME> is required")?;
    let files: Vec<PathBuf> = o.rest.iter().map(PathBuf::from).collect();
    let manifest = library(o)?.import(name, &files, o.quota)?;
    println!(
        "imported {} ({}, quantization {}): {} file(s), verified LOCAL_DIGEST_ONLY -- the \
         publisher's authenticity is not known; not ready for inference",
        manifest.name,
        manifest.format,
        shown(manifest.quantization.as_deref().unwrap_or("-")),
        manifest.files.len()
    );
    for entry in &manifest.files {
        println!(
            "  {} {} {} bytes {}",
            entry.sha256, entry.format, entry.bytes, entry.file
        );
    }
    Ok(0)
}

fn list(o: &Options) -> Result<u8, String> {
    let models = library(o)?.list()?;
    for m in &models {
        if o.json {
            println!("{}", json_line(m));
        } else {
            println!(
                "{} {} {} {} {} file(s) {} bytes license={}",
                m.name,
                m.format,
                shown(m.architecture.as_deref().unwrap_or("-")),
                shown(m.quantization.as_deref().unwrap_or("-")),
                m.files.len(),
                m.weight_bytes(),
                shown(m.license.as_deref().unwrap_or("not stated"))
            );
        }
    }
    Ok(0)
}

fn one_name(o: &Options) -> Result<&str, String> {
    match o.rest.as_slice() {
        [name] => Ok(name.as_str()),
        _ => Err("exactly one model name is required".to_owned()),
    }
}

fn verify(o: &Options) -> Result<u8, String> {
    let name = one_name(o)?;
    let report = library(o)?.verify(name)?;
    let mut corrupt = false;
    for (entry, state) in &report {
        match state {
            FileState::Verified => println!("VERIFIED {} {}", entry.sha256, entry.file),
            FileState::Corrupt(why) => {
                corrupt = true;
                println!("CORRUPT {} {}: {why}", entry.sha256, entry.file);
            }
        }
    }
    Ok(if corrupt { EXIT_REFUSED } else { 0 })
}

fn remove(o: &Options) -> Result<u8, String> {
    let name = one_name(o)?;
    let removed = library(o)?.remove(name)?;
    println!("removed {name}; {removed} object(s) no other model named were deleted");
    Ok(0)
}

fn recommend(o: &Options) -> Result<u8, String> {
    let facts = hardware::detect(o.vram_gib);
    let show = |v: Option<u64>| v.map_or("unknown".to_owned(), |b| b.to_string());
    println!(
        "host: {} {} threads={} ram_total={} ram_available={} vram={}",
        facts.os,
        facts.arch,
        show(facts.threads),
        show(facts.ram_total),
        show(facts.ram_available),
        facts.vram.map_or(
            "unknown (no GPU is probed; --vram-gib states it)".to_owned(),
            |v| v.to_string()
        )
    );
    if o.library.is_none() {
        return Ok(0);
    }
    let context = o.context.unwrap_or(DEFAULT_CONTEXT);
    for m in library(o)?.list()? {
        let e = hardware::estimate(&m, context, &facts);
        println!(
            "{} {} (needed={} available={} {}): {}",
            m.name,
            e.fit.word(),
            show(e.needed),
            show(e.budget),
            e.place,
            e.why
        );
    }
    Ok(0)
}

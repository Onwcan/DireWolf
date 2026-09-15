//! `protogen` — write, or check, everything generated from `dwk-proto`.
//!
//! ```text
//! protogen write [--root DIR]    regenerate schemas/ and docs/DWKP_OPERATIONS.md
//! protogen check [--root DIR]    regenerate in memory; exit 1 if any file differs
//! ```
//!
//! Generation is deterministic: no timestamps, no absolute paths, no map
//! iteration order, no toolchain versions in the output. `check` is what CI
//! runs; it never writes. A human regenerates deliberately and commits the
//! result, so a schema change is always a reviewed diff.
//!
//! The Python bindings are generated from the schemas this writes, by
//! `scripts/gen_proto_python.py`; `make schema` runs both in order.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use dwk_proto::dwkp::registry::{OPERATIONS, WireStatus};
use dwk_proto::json::{Number, Value, jcs, number::format_es};
use dwk_proto::schema::emit;

/// Directories whose contents are entirely generated. Files in them that the
/// generator did not produce are drift (a removed message must not linger).
const GENERATED_DIRS: &[&str] = &[
    "schemas/common",
    "schemas/dwkp",
    "schemas/dwcp",
    "schemas/events",
];

const INVENTORY_DOC: &str = "docs/DWKP_OPERATIONS.md";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut root = PathBuf::from(".");
    let mut command = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => match iter.next() {
                Some(dir) => root = PathBuf::from(dir),
                None => return usage("--root needs a directory"),
            },
            "write" | "check" => command = Some(arg.clone()),
            other => return usage(&format!("unknown argument {other}")),
        }
    }
    let outputs = generate();
    match command.as_deref() {
        Some("write") => write(&root, &outputs),
        Some("check") => check(&root, &outputs),
        _ => usage("expected `write` or `check`"),
    }
}

fn usage(problem: &str) -> ExitCode {
    eprintln!("protogen: {problem}");
    eprintln!("usage: protogen (write|check) [--root DIR]");
    ExitCode::from(2)
}

/// Every generated file, keyed by repository-relative path.
fn generate() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (path, doc) in emit::all() {
        out.insert(format!("schemas/{path}"), pretty(&doc));
    }
    out.insert(INVENTORY_DOC.to_owned(), inventory_markdown());
    out
}

fn write(root: &Path, outputs: &BTreeMap<String, String>) -> ExitCode {
    for dir in GENERATED_DIRS {
        let dir = root.join(dir);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let rel = relative(root, &entry.path());
                if !outputs.contains_key(&rel) {
                    if let Err(e) = std::fs::remove_file(entry.path()) {
                        eprintln!("protogen: cannot remove stale {rel}: {e}");
                        return ExitCode::FAILURE;
                    }
                    println!("removed {rel}");
                }
            }
        }
    }
    for (rel, content) in outputs {
        let path = root.join(rel);
        if std::fs::read_to_string(&path).is_ok_and(|existing| &existing == content) {
            continue;
        }
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            eprintln!("protogen: cannot create {}: {e}", parent.display());
            return ExitCode::FAILURE;
        }
        if let Err(e) = std::fs::write(&path, content) {
            eprintln!("protogen: cannot write {rel}: {e}");
            return ExitCode::FAILURE;
        }
        println!("wrote {rel}");
    }
    ExitCode::SUCCESS
}

fn check(root: &Path, outputs: &BTreeMap<String, String>) -> ExitCode {
    let mut drift = Vec::new();
    for (rel, content) in outputs {
        match std::fs::read_to_string(root.join(rel)) {
            Ok(existing) if &existing == content => {}
            Ok(_) => drift.push(format!("differs: {rel}")),
            Err(_) => drift.push(format!("missing: {rel}")),
        }
    }
    for dir in GENERATED_DIRS {
        if let Ok(entries) = std::fs::read_dir(root.join(dir)) {
            for entry in entries.flatten() {
                let rel = relative(root, &entry.path());
                if !outputs.contains_key(&rel) {
                    drift.push(format!("unexpected: {rel}"));
                }
            }
        }
    }
    if drift.is_empty() {
        println!(
            "protogen: {} generated files match the protocol source",
            outputs.len()
        );
        return ExitCode::SUCCESS;
    }
    for line in &drift {
        eprintln!("protogen: {line}");
    }
    eprintln!(
        "protogen: generated files have drifted from crates/dwk-proto. Run `make schema` and \
         commit the result; never edit generated files by hand."
    );
    ExitCode::FAILURE
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

// ---- deterministic pretty printer -----------------------------------------

/// Two-space indentation, members in emission order, strings escaped exactly as
/// RFC 8785 does, numbers in ECMAScript form. Not canonical — schemas are for
/// people too — but a pure function of the value.
fn pretty(value: &Value) -> String {
    let mut out = String::new();
    write_pretty(&mut out, value, 0);
    out.push('\n');
    out
}

fn write_pretty(out: &mut String, value: &Value, indent: usize) {
    match value {
        Value::Array(items) if items.is_empty() => out.push_str("[]"),
        Value::Array(items) => {
            // Short arrays of scalars stay on one line; they are enum lists.
            if items
                .iter()
                .all(|v| !matches!(v, Value::Array(_) | Value::Object(_)))
                && items.len() <= 16
            {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    write_pretty(out, item, indent);
                }
                out.push(']');
                return;
            }
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                push_indent(out, indent + 1);
                write_pretty(out, item, indent + 1);
                out.push_str(if i + 1 < items.len() { ",\n" } else { "\n" });
            }
            push_indent(out, indent);
            out.push(']');
        }
        Value::Object(object) if object.is_empty() => out.push_str("{}"),
        Value::Object(object) => {
            out.push_str("{\n");
            let count = object.len();
            for (i, (key, member)) in object.iter().enumerate() {
                push_indent(out, indent + 1);
                out.push_str(&jcs::to_canonical_string(&Value::String(key.to_owned())));
                out.push_str(": ");
                write_pretty(out, member, indent + 1);
                out.push_str(if i + 1 < count { ",\n" } else { "\n" });
            }
            push_indent(out, indent);
            out.push('}');
        }
        Value::Number(Number::Float(f)) => out.push_str(&format_es(*f).unwrap_or_default()),
        scalar => out.push_str(&jcs::to_canonical_string(scalar)),
    }
}

fn push_indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

// ---- operation inventory document -------------------------------------------

fn inventory_markdown() -> String {
    let mut md = String::new();
    let _ = writeln!(
        md,
        "<!-- GENERATED by tools/protogen from crates/dwk-proto/src/dwkp/registry.rs. Do not edit; run `make schema`. -->"
    );
    let _ = writeln!(md);
    let _ = writeln!(md, "# DWKP operation inventory");
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "The authoritative list of every operation the architecture names for the kernel protocol, \
         and the only place an operation's second-path argument is recorded. **Source of truth: \
         [`registry.rs`](../crates/dwk-proto/src/dwkp/registry.rs)**; this page and \
         [`schemas/dwkp/operations.json`](../schemas/dwkp/operations.json) are generated from it \
         and CI fails if either drifts."
    );
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "**Defined** operations exist on the wire. **Reserved** operations are named by the \
         architecture but have no message schema: a message naming one is rejected as \
         `PROTOCOL_UNKNOWN_OPERATION`, exactly like a misspelled one, until its owning milestone \
         designs its payload and re-examines its second-path argument. Changing this inventory \
         requires the protocol change review in [CONTRIBUTING.md](../CONTRIBUTING.md)."
    );
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "| Operation | Layer | Status | Request | Responses | Initiator → receiver | Semantics owner | Effect | Authority |"
    );
    let _ = writeln!(md, "|---|---|---|---|---|---|---|---|---|");
    for op in OPERATIONS {
        let request = op
            .request
            .map_or_else(|| "—".to_owned(), |r| format!("`{r}`"));
        let responses = if op.responses.is_empty() {
            "—".to_owned()
        } else {
            op.responses
                .iter()
                .map(|r| format!("`{r}`"))
                .collect::<Vec<_>>()
                .join("<br>")
        };
        let _ = writeln!(
            md,
            "| **{}** | {} | {} | {} | {} | {} → {} | {} | {} | {} |",
            op.name,
            op.layer.as_str(),
            op.status.as_str(),
            request,
            responses,
            op.initiator,
            op.receiver,
            op.semantics_owner,
            yes_no(op.effect_bearing),
            yes_no(op.authority_bearing),
        );
    }
    for (heading, status) in [
        ("Defined operations", WireStatus::Defined),
        ("Reserved operations", WireStatus::Reserved),
    ] {
        let _ = writeln!(md);
        let _ = writeln!(md, "## {heading}");
        for op in OPERATIONS.iter().filter(|o| o.status == status) {
            let _ = writeln!(md);
            let _ = writeln!(md, "### {}", op.name);
            let _ = writeln!(md);
            let _ = writeln!(md, "- **Carries:** {}", op.carries);
            let _ = writeln!(md, "- **Consumer:** {}", op.consumer);
            let _ = writeln!(
                md,
                "- **Can directly cause an effect:** {}",
                yes_no(op.effect_bearing)
            );
            let _ = writeln!(md, "- **Semantics owned by:** {}", op.semantics_owner);
            let _ = writeln!(
                md,
                "- **Why it is not a second path from cognition to effect:** {}",
                op.second_path
            );
        }
    }
    md
}

const fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

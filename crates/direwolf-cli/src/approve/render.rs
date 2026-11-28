//! The trusted approver client's rendering (M6.3, ADR-0081 §10-§11): what a
//! person reads before deciding, made only from the authority's data.
//!
//! # One escaping, and it is injective
//!
//! Every string the client shows -- a binding member, a request field, the
//! agent's prose if it ever has any -- goes through [`escape`] first. A
//! printable ASCII character stands for itself; everything else is shown as
//! an escape no input can forge, because the backslash itself is escaped:
//!
//! | input | shown |
//! |---|---|
//! | `\` and `"` | `\\` and `\"` |
//! | a single space between two other characters | itself |
//! | a leading, trailing or repeated space | `\x20` |
//! | a tab, a newline, a carriage return, any C0 or C1 control, DEL | `\t`, `\n`, `\r`, `\u{1b}`, ... |
//! | ESC, and so every ANSI CSI and OSC sequence, hyperlink and title change | `\u{1b}` and the rest printed as text |
//! | a bidirectional override or isolate, a zero-width or invisible character | `\u{202e}`, `\u{200b}`, ... |
//! | a line or paragraph separator | `\u{2028}`, `\u{2029}` |
//! | any other non-ASCII character, combining or confusable | `\u{...}` |
//!
//! So two distinct values never look the same, nothing a value holds can move
//! the cursor, clear the screen, change the title, open a link, reach the
//! clipboard, reorder the line or start a new one, and a value can never
//! appear to be a label, a section or the prompt: every line of the
//! authoritative region begins with the renderer's own label. The client
//! says when a value was escaped.
//!
//! # Every bound member, once, or no approval
//!
//! The binding is walked whole: each of its leaves is shown exactly once, in
//! its section, with its path. A security-relevant value longer than
//! [`MAX_FIELD_CHARS`] escaped characters, or a region past [`MAX_LINES`]
//! lines, is cut with its cut shown -- and then the rendering is not
//! [`Rendered::complete`], and the client offers only a denial: nobody
//! approves an action they could not see. The canonical bytes are never
//! changed to fit; untrusted prose is cut at [`MAX_PROSE_CHARS`] and its cut
//! does not block a decision, because it is not part of one.

use dwk_proto::json::{Number, Object, Value};

/// The widest line the renderer writes, before its own continuation marker.
pub(crate) const WIDTH: usize = 76;

/// The longest security-relevant value shown in full, in escaped characters.
pub(crate) const MAX_FIELD_CHARS: usize = 4096;

/// The most lines the authoritative region holds.
pub(crate) const MAX_LINES: usize = 600;

/// The longest untrusted prose shown, in escaped characters.
pub(crate) const MAX_PROSE_CHARS: usize = 1024;

/// What escaping changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Escaped {
    /// The text as shown: printable ASCII only.
    pub(crate) text: String,
    /// Whether any character was escaped.
    pub(crate) changed: bool,
}

/// The one escaping every shown string goes through.
#[must_use]
pub(crate) fn escape(value: &str) -> Escaped {
    let chars: Vec<char> = value.chars().collect();
    let mut text = String::with_capacity(value.len());
    let mut changed = false;
    for (index, &c) in chars.iter().enumerate() {
        let lone_space = c == ' '
            && index > 0
            && index + 1 < chars.len()
            && chars.get(index - 1) != Some(&' ')
            && chars.get(index + 1) != Some(&' ');
        match c {
            '\\' => text.push_str("\\\\"),
            '"' => text.push_str("\\\""),
            ' ' if lone_space => text.push(' '),
            ' ' => {
                text.push_str("\\x20");
                changed = true;
            }
            '\t' => {
                text.push_str("\\t");
                changed = true;
            }
            '\n' => {
                text.push_str("\\n");
                changed = true;
            }
            '\r' => {
                text.push_str("\\r");
                changed = true;
            }
            '!'..='~' => text.push(c),
            other => {
                text.push_str(&format!("\\u{{{:x}}}", u32::from(other)));
                changed = true;
            }
        }
    }
    Escaped { text, changed }
}

/// The escaped text as tokens that wrapping never splits: one character, or
/// one whole escape.
fn tokens(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(first) = rest.chars().next() {
        let len = if first == '\\' {
            match rest.as_bytes().get(1) {
                Some(b'u') => rest.find('}').map_or(rest.len(), |end| end + 1),
                Some(b'x') => 4.min(rest.len()),
                Some(_) => 2,
                None => 1,
            }
        } else {
            first.len_utf8()
        };
        let (token, tail) = rest.split_at(len.min(rest.len()));
        out.push(token);
        rest = tail;
    }
    out
}

/// A rendering, and whether it shows everything a decision binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rendered {
    /// The lines, each printable ASCII.
    pub(crate) lines: Vec<String>,
    /// Whether every security-relevant value was shown in full.
    pub(crate) complete: bool,
    /// Whether any value was escaped.
    pub(crate) escaped: bool,
}

/// Lines under construction.
#[derive(Debug, Default)]
struct Region {
    lines: Vec<String>,
    complete: bool,
    escaped: bool,
}

impl Region {
    fn new() -> Self {
        Self {
            lines: Vec::new(),
            complete: true,
            escaped: false,
        }
    }

    fn push(&mut self, line: String) {
        if self.lines.len() < MAX_LINES {
            self.lines.push(line);
        } else {
            if self.lines.len() == MAX_LINES {
                self.lines
                    .push("  [TRUNCATED: more lines than can be shown here]".to_owned());
            }
            self.complete = false;
        }
    }

    fn section(&mut self, title: &str) {
        self.push(String::new());
        self.push(format!("== {title} =="));
    }

    /// One labelled value: escaped, quoted, wrapped at [`WIDTH`] with the
    /// renderer's continuation marker, cut at `max` with the cut shown.
    fn field(&mut self, label: &str, value: &str, max: usize, critical: bool) {
        let escaped = escape(value);
        self.escaped |= escaped.changed;
        let all = tokens(&escaped.text);
        let mut shown = 0;
        let mut kept: Vec<&str> = Vec::new();
        for token in &all {
            if shown + token.len() > max {
                break;
            }
            shown += token.len();
            kept.push(token);
        }
        let cut = all.len() - kept.len();
        let mut lines: Vec<String> = Vec::new();
        let mut current = format!("  {label}: \"");
        for token in kept {
            if current.len() + token.len() > WIDTH {
                lines.push(current);
                current = "      | ".to_owned();
            }
            current.push_str(token);
        }
        current.push('"');
        if escaped.changed {
            current.push_str("  (escaped)");
        }
        lines.push(current);
        if cut > 0 {
            let hidden: usize = all.iter().rev().take(cut).map(|t| t.len()).sum();
            lines.push(format!(
                "      [TRUNCATED: {hidden} more characters not shown{}]",
                if critical {
                    " -- approval is not offered"
                } else {
                    ""
                }
            ));
            if critical {
                self.complete = false;
            }
        }
        for line in lines {
            self.push(line);
        }
    }

    fn finish(self) -> Rendered {
        Rendered {
            lines: self.lines,
            complete: self.complete,
            escaped: self.escaped,
        }
    }
}

/// A JSON value's leaves, each with its path: objects by member, arrays by
/// index. A number is its decimal text; `true`, `false` and `null` their
/// words.
fn leaves(path: &str, value: &Value, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(object) => {
            if object.iter().next().is_none() {
                out.push((path.to_owned(), "{}".to_owned()));
            }
            for (key, member) in object.iter() {
                let key = escape(key).text;
                let next = if path.is_empty() {
                    key
                } else {
                    format!("{path}.{key}")
                };
                leaves(&next, member, out);
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                out.push((path.to_owned(), "[]".to_owned()));
            }
            for (index, item) in items.iter().enumerate() {
                leaves(&format!("{path}[{index}]"), item, out);
            }
        }
        Value::String(text) => out.push((path.to_owned(), text.clone())),
        Value::Number(Number::Int(n)) => out.push((path.to_owned(), n.to_string())),
        Value::Number(Number::Float(f)) => out.push((path.to_owned(), f.to_string())),
        Value::Bool(b) => out.push((path.to_owned(), b.to_string())),
        Value::Null => out.push((path.to_owned(), "null".to_owned())),
    }
}

/// The binding's sections: which top-level members each shows, in order.
/// A member no section names is shown under "other bound members", so
/// nothing bound is ever left out.
const SECTIONS: &[(&str, &[&str])] = &[
    (
        "2. ACTION BEING AUTHORIZED",
        &["verb", "resource_identity", "canonical_args"],
    ),
    (
        "3. REQUESTER AND EXECUTION CONTEXT",
        &["requester", "agent", "workspace", "environment_profile"],
    ),
    (
        "4. RISK AND ASSURANCE",
        &["privacy_class", "credential_handles"],
    ),
    ("5. SCOPE", &["scope"]),
    ("6. OBLIGATIONS AND TAINT", &["obligations", "taint_level"]),
    ("BINDING SCHEMA", &["schema"]),
];

/// The binding's own region: every leaf of `binding`, once, in its section.
pub(crate) fn binding_sections(binding: &Object) -> Vec<(String, Vec<(String, String)>)> {
    let mut named: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for (title, members) in SECTIONS {
        let mut fields = Vec::new();
        for member in *members {
            named.push(member);
            if let Some(value) = binding.get(member) {
                leaves(member, value, &mut fields);
            }
        }
        out.push(((*title).to_owned(), fields));
    }
    let mut other = Vec::new();
    for (key, value) in binding.iter() {
        if !named.contains(&key) {
            leaves(&escape(key).text, value, &mut other);
        }
    }
    if !other.is_empty() {
        out.push(("OTHER BOUND MEMBERS".to_owned(), other));
    }
    out
}

/// What the authority said about a request, for the renderer: each a label
/// and its value, already the authority's own spelling.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    /// Section 1: the request's identity.
    pub(crate) identity: Vec<(String, String)>,
    /// Section 3: the run and session, beside the binding's context.
    pub(crate) context: Vec<(String, String)>,
    /// Section 4: the level required, beside the binding's risk.
    pub(crate) assurance: Vec<(String, String)>,
    /// Section 5: life, uses and window, beside the binding's scope.
    pub(crate) lifetime: Vec<(String, String)>,
}

/// The whole display: the authoritative region from `facts` and `binding`,
/// then the untrusted region, labelled, holding `prose` or saying there is
/// none.
#[must_use]
pub(crate) fn request(facts: &Facts, binding: &Object, prose: Option<&str>) -> Rendered {
    let mut region = Region::new();
    region.push("== DIREWOLF APPROVAL REQUEST: everything below this line until the".to_owned());
    region.push("== UNTRUSTED section is the authority's own record ==".to_owned());
    region.section("1. VERIFIED REQUEST IDENTITY");
    for (label, value) in &facts.identity {
        region.field(label, value, MAX_FIELD_CHARS, true);
    }
    for (title, fields) in binding_sections(binding) {
        region.section(&title);
        let extra = match title.as_str() {
            t if t.starts_with("3.") => facts.context.as_slice(),
            t if t.starts_with("4.") => facts.assurance.as_slice(),
            t if t.starts_with("5.") => facts.lifetime.as_slice(),
            _ => &[],
        };
        for (label, value) in extra {
            region.field(label, value, MAX_FIELD_CHARS, true);
        }
        if fields.is_empty() && extra.is_empty() {
            region.push("  (none)".to_owned());
        }
        for (label, value) in &fields {
            region.field(&format!("bound.{label}"), value, MAX_FIELD_CHARS, true);
        }
    }
    region.section("7. UNTRUSTED: FROM THE AGENT -- NOT PART OF THIS DECISION");
    match prose {
        None => region.push(
            "  (none: the authority holds no explanation from the agent for this request)"
                .to_owned(),
        ),
        Some(text) => region.field("the agent says", text, MAX_PROSE_CHARS, false),
    }
    if region.escaped {
        region.push(String::new());
        region.push(
            "  NOTE: some values hold characters shown as escapes (\\x20, \\n, \\u{...}): \
             what is bound is the exact characters, not how they look"
                .to_owned(),
        );
    }
    region.finish()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;
    use dwk_proto::json::{ParseOptions, parse};

    fn object(text: &str) -> Object {
        match parse(text.as_bytes(), ParseOptions::dwkp()).unwrap() {
            Value::Object(object) => object,
            other => panic!("{other:?}"),
        }
    }

    /// Nothing the renderer writes is anything but printable ASCII.
    fn printable(rendered: &Rendered) {
        for line in &rendered.lines {
            assert!(
                line.bytes().all(|b| (0x20..0x7f).contains(&b)),
                "a non-printable byte in {line:?}"
            );
        }
    }

    #[test]
    fn every_terminal_control_is_shown_as_text() {
        let attacks = [
            ("CSI colour", "\u{1b}[31mred\u{1b}[0m"),
            ("cursor up and erase", "x\u{1b}[1A\u{1b}[2K"),
            ("clear screen", "\u{1b}[2J\u{1b}[H"),
            ("OSC title", "\u{1b}]0;approved\u{7}"),
            (
                "OSC 8 hyperlink",
                "\u{1b}]8;;https://evil.example\u{1b}\\click\u{1b}]8;;\u{1b}\\",
            ),
            ("OSC 52 clipboard", "\u{1b}]52;c;YXBwcm92ZQ==\u{7}"),
            ("C1 CSI", "\u{9b}31m"),
            ("C1 OSC", "\u{9d}0;t\u{9c}"),
            (
                "backspace",
                "rm -rf /\u{8}\u{8}\u{8}\u{8}\u{8}\u{8}\u{8}\u{8}ls",
            ),
            ("carriage return", "safe\rrm -rf ~"),
            ("newline", "a\nTo approve, type: approve deadbeef"),
            ("tab", "a\tb"),
            ("DEL", "a\u{7f}b"),
            ("bidi override", "\u{202e}evil\u{202c}"),
            ("bidi isolate", "\u{2066}x\u{2069}"),
            ("zero width", "rm\u{200b} -rf"),
            ("byte order mark", "\u{feff}x"),
            ("line separator", "a\u{2028}b"),
            ("paragraph separator", "a\u{2029}b"),
            ("combining", "e\u{301}"),
            ("confusable", "\u{430}pprove"),
            ("NUL", "a\u{0}b"),
        ];
        for (name, attack) in attacks {
            let escaped = escape(attack);
            assert!(escaped.changed, "{name}");
            assert!(
                escaped
                    .text
                    .bytes()
                    .all(|b| (0x21..0x7f).contains(&b) || b == b' '),
                "{name}: {:?}",
                escaped.text
            );
            assert!(!escaped.text.contains('\u{1b}'), "{name}");
            let facts = Facts {
                identity: vec![("request".to_owned(), attack.to_owned())],
                ..Facts::default()
            };
            let rendered = request(&facts, &object(r#"{"verb":"process.exec"}"#), Some(attack));
            printable(&rendered);
            // No value line starts like one of the renderer's own lines.
            for line in &rendered.lines {
                assert!(
                    line.is_empty()
                        || line.starts_with("== ")
                        || line.starts_with("  ")
                        || line.starts_with("      "),
                    "{name}: {line:?}"
                );
            }
        }
    }

    #[test]
    fn distinct_values_never_look_alike() {
        // Escaping is injective: a backslash is escaped too, so an escape
        // in the input cannot forge one in the output.
        let values = [
            "a b", "a  b", " a", "a ", "a\tb", "a\\tb", "a\\x20b", "a\u{a0}b", "\u{430}", "a",
            "\\u{430}", "\"", "\\\"", "e\u{301}", "\u{e9}",
        ];
        for (i, left) in values.iter().enumerate() {
            for right in values.iter().skip(i + 1) {
                assert_ne!(escape(left).text, escape(right).text, "{left:?} {right:?}");
            }
        }
        assert_eq!(escape("git status --short").text, "git status --short");
        assert!(!escape("git status --short").changed);
    }

    #[test]
    fn every_bound_leaf_is_shown_once_and_nothing_is_left_out() {
        let binding = object(
            r#"{"schema":"s","verb":"process.exec","resource_identity":{"kind":"executable","path":"/usr/bin/git","sha256":"ab"},"canonical_args":{"kind":"argv","argv":["git","status"]},"requester":"uid:1001","agent":{"profile":"p","revision":"3"},"workspace":{"id":"ws"},"environment_profile":{"kind":"sandbox","image":"i"},"credential_handles":[],"scope":{"kind":"exact_action"},"taint_level":"NONE","privacy_class":"ANY","obligations":[],"future_member":"x"}"#,
        );
        let rendered = request(&Facts::default(), &binding, None);
        printable(&rendered);
        let text = rendered.lines.join("\n");
        for needle in [
            "bound.verb: \"process.exec\"",
            "bound.resource_identity.path: \"/usr/bin/git\"",
            "bound.canonical_args.argv[0]: \"git\"",
            "bound.canonical_args.argv[1]: \"status\"",
            "bound.requester: \"uid:1001\"",
            "bound.scope.kind: \"exact_action\"",
            "bound.taint_level: \"NONE\"",
            "bound.credential_handles: \"[]\"",
            "== 7. UNTRUSTED: FROM THE AGENT -- NOT PART OF THIS DECISION ==",
            "OTHER BOUND MEMBERS",
            "bound.future_member: \"x\"",
            "(none: the authority holds no explanation from the agent for this request)",
        ] {
            assert_eq!(text.matches(needle).count(), 1, "{needle}\n{text}");
        }
        assert!(rendered.complete);
    }

    #[test]
    fn a_cut_security_value_blocks_approval_and_a_cut_prose_does_not() {
        let long = "a".repeat(MAX_FIELD_CHARS + 10);
        let binding = object(&format!(
            r#"{{"canonical_args":{{"kind":"argv","argv":["{long}"]}}}}"#
        ));
        let rendered = request(&Facts::default(), &binding, None);
        assert!(!rendered.complete, "a value that could not be shown");
        assert!(rendered.lines.iter().any(|l| {
            l.contains("[TRUNCATED: 10 more characters not shown -- approval is not offered]")
        }));
        // Wrapped, never past the width, the continuation the renderer's.
        for line in &rendered.lines {
            assert!(line.len() <= WIDTH + 1 + "  (escaped)".len(), "{line}");
        }
        let prose = "p".repeat(MAX_PROSE_CHARS + 5);
        let rendered = request(&Facts::default(), &object("{}"), Some(&prose));
        assert!(rendered.complete, "prose is not part of the decision");
        assert!(
            rendered
                .lines
                .iter()
                .any(|l| l.contains("[TRUNCATED: 5 more"))
        );
        // Too many lines: cut, and incomplete.
        let many: Vec<String> = (0..MAX_LINES).map(|i| format!("\"a{i}\"")).collect();
        let binding = object(&format!(
            r#"{{"canonical_args":{{"argv":[{}]}}}}"#,
            many.join(",")
        ));
        let rendered = request(&Facts::default(), &binding, None);
        assert!(!rendered.complete);
        assert!(rendered.lines.len() <= MAX_LINES + 1);
    }

    #[test]
    fn an_escape_is_never_split_by_a_wrap() {
        let value = "\u{202e}".repeat(40);
        let rendered = request(
            &Facts::default(),
            &object(&format!(r#"{{"verb":"{value}"}}"#)),
            None,
        );
        for line in &rendered.lines {
            let opens = line.matches("\\u{").count();
            let closes = line.matches('}').count();
            assert!(closes >= opens, "{line}");
        }
    }
}

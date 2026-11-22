"""F-13 and F-15: what the documents say, against the build and the records.

`make docs` (`dwcheck links`) proves that a relative link resolves and that an
ADR citation names a record that exists. It cannot tell whether a command a
document tells an operator to run exists, whether a milestone the README calls
complete is complete in the roadmap, or whether a record still says "hosted
evidence pending" after a hosted run exercised it. Each check below reads
both sides from the repository -- the binaries' usage text from their Rust
source, the milestones from the roadmap's headings, the records' statuses from
`docs/adr/` -- so neither side is a copy kept in this file.

Every check is a pure function of text and is shown twice: once holding for
the repository, once failing on a deliberately broken fixture made from the
repository's own text, so a check that can no longer fail is itself a failure.

What these checks do not cover: the design documents (ARCHITECTURE.md,
POLICY.md and the others) describe V1's command line, which is M17's; only the
documents that say what is built are held to the binaries, and PRODUCT_SPEC.md
to carrying an "As built" note wherever it shows a command that does not exist.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Documents that say what is built and how to run it: every command and flag
# they show must exist.
AS_BUILT_DOCS = (
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "docs/OPERATIONS.md",
    "docs/MODELS.md",
    "docs/BROKER_HARDENING.md",
    "docs/PRE_M6_REMEDIATION.md",
    "docs/F03_EFFECTIVE_POSTURE.md",
    "docs/F05_USERNS_LSM.md",
    "docs/F06_EGRESS_ALLOWLIST.md",
    "docs/F12_POLICY_PACK_USABILITY.md",
    "docs/F18_APPROVER_IDENTITY.md",
)
BINARIES = ("direwolf", "dwkd-authority", "dwkd-broker")
# Every binary answers these; none is listed in a usage text's flag table.
UNIVERSAL_FLAGS = frozenset({"-h", "--help", "-V", "--version"})


def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_bytes().decode("utf-8")


def _broken(text: str, old: str, new: str) -> str:
    """A fixture: `text` with exactly one `old` replaced."""
    assert text.count(old) == 1, (text.count(old), old)
    return text.replace(old, new)


def _flat(text: str) -> str:
    return " ".join(text.split())


# --- the binaries' own usage text, read from their source ---------------------

_ESCAPES = {"n": "\n", "t": "\t", '"': '"', "\\": "\\", "'": "'", "0": "\0"}


def rust_literal_at(source: str, start: int) -> str:
    """The value of the Rust string literal whose opening quote is at `start`.

    A backslash before a line break drops the break and the next line's
    leading whitespace, as Rust does.
    """
    assert source[start] == '"', source[start : start + 20]
    out: list[str] = []
    i = start + 1
    while source[i] != '"':
        if source[i] == "\\":
            escaped = source[i + 1]
            if escaped == "\n":
                i += 2
                while source[i] in " \t\r\n":
                    i += 1
                continue
            out.append(_ESCAPES[escaped])
            i += 2
            continue
        out.append(source[i])
        i += 1
    return "".join(out)


def rust_const(source: str, name: str) -> str:
    match = re.search(rf'const {name}: &str = "', source)
    assert match, name
    return rust_literal_at(source, match.end() - 1)


def rust_help(source: str) -> str:
    """The format string of `fn help()`'s `format!`."""
    at = source.index("fn help() -> String {")
    return rust_literal_at(source, source.index('"', source.index("format!(", at)))


def usage_texts(read: Callable[[str], str] = _read) -> dict[str, str]:
    """Each binary's usage text as it prints it (placeholders filled)."""
    serve = rust_const(read("crates/dwkd-authority/src/server/config.rs"), "SERVE_USAGE")
    authority = rust_help(read("crates/dwkd-authority/src/main.rs"))
    broker = rust_help(read("crates/dwkd-broker/src/main.rs"))
    return {
        "direwolf": rust_const(read("crates/direwolf-cli/src/main.rs"), "USAGE"),
        "direwolf models": rust_const(read("crates/direwolf-cli/src/models/mod.rs"), "USAGE"),
        "dwkd-authority": authority.replace("{SERVE_USAGE}", serve).replace(
            "{NAME}", "dwkd-authority"
        ),
        "dwkd-broker": broker.replace("{NAME}", "dwkd-broker"),
    }


_FLAG = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]*|-[A-Za-z])(?![\w-])")


@dataclass(frozen=True)
class Surface:
    """What each binary accepts: its subcommands and its flags."""

    commands: Mapping[str, frozenset[str]]
    flags: Mapping[str, frozenset[str]]


def surface(usages: Mapping[str, str], cli_source: str) -> Surface:
    # The CLI's commands are its dispatch table's, so an alias works too; its
    # tests (which name a command that must not exist) are not the table.
    product = cli_source[: cli_source.index("#[cfg(test)]")]
    cli = frozenset(re.findall(r'\["([a-z][a-z-]*)"', product))
    commands = {
        "direwolf": cli,
        "direwolf models": frozenset(
            re.findall(r"^\s*direwolf models ([a-z]+)", usages["direwolf models"], re.M)
        ),
        "dwkd-authority": frozenset(
            re.findall(r"^\s*dwkd-authority ([a-z][a-z-]*)", usages["dwkd-authority"], re.M)
        ),
        "dwkd-broker": frozenset(
            re.findall(r"^\s*dwkd-broker ([a-z][a-z-]*)", usages["dwkd-broker"], re.M)
        ),
    }
    flags = {
        name: frozenset(_FLAG.findall(text)) | UNIVERSAL_FLAGS for name, text in usages.items()
    }
    return Surface(commands, flags)


def the_surface() -> Surface:
    return surface(usage_texts(), _read("crates/direwolf-cli/src/main.rs"))


# --- code in Markdown -------------------------------------------------------------

_FENCE = re.compile(r"^\s*(```|~~~)")
_SPAN = re.compile(r"`([^`\n]+)`")


def code_fragments(text: str) -> list[tuple[int, str]]:
    """(line, code) for every inline code span and every fenced code line; a
    fenced line ending in a backslash is joined to the next, and a shell
    comment is dropped."""
    fragments: list[tuple[int, str]] = []
    fenced = False
    pending: tuple[int, str] | None = None
    for number, line in enumerate(text.splitlines(), 1):
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            code = re.sub(r"(^|\s)#\s.*$", "", line).rstrip()
            if pending is not None:
                number, code = pending[0], pending[1] + " " + code.strip()
            if code.endswith("\\"):
                pending = (number, code[:-1].rstrip())
                continue
            pending = None
            fragments.append((number, code))
        else:
            fragments.extend((number, span) for span in _SPAN.findall(line))
    return fragments


_COMMAND = re.compile(r"(?<![\w.-])(direwolf|dwkd-authority|dwkd-broker)(?![\w-])((?:[ \t]+\S+)*)")
_WORD = re.compile(r"^[a-z][a-z-]*$")
# A flag as a usage line writes it: bare, bracketed, or with its value.
_FLAG_TOKEN = re.compile(r"^[\[(]*(--[a-z][a-z0-9-]*|-[A-Za-z])(?:=.*)?[\],.;:)]*$")
# A binary's name as cargo's argument is a package or a target, not a command.
_BUILT_BY_CARGO = re.compile(r"(?:^|\s)(?:-p|--package|--bin|--test)\s+$")
DASH = "\u2013"  # the en dash the documents write ranges with


def stale_commands(docs: Mapping[str, str], shape: Surface) -> list[str]:
    """Every command or flag a document shows that its binary does not have."""
    findings: list[str] = []
    for rel, text in docs.items():
        for line, code in code_fragments(text):
            for match in _COMMAND.finditer(code):
                binary, tokens = match.group(1), match.group(2).split()
                if not tokens or not (_WORD.match(tokens[0]) or tokens[0].startswith("-")):
                    continue
                if _BUILT_BY_CARGO.search(code[: match.start()]):
                    continue  # `cargo test -p dwkd-broker --bin ...` names a package
                scope = binary
                if _WORD.match(tokens[0]):
                    if tokens[0] not in shape.commands[binary]:
                        findings.append(f"{rel}:{line}: `{binary} {tokens[0]}` does not exist")
                        continue
                    if binary == "direwolf" and tokens[0] == "models":
                        scope = "direwolf models"
                        rest = tokens[1:]
                        if rest and _WORD.match(rest[0]) and rest[0] not in shape.commands[scope]:
                            findings.append(f"{rel}:{line}: `{scope} {rest[0]}` does not exist")
                for token in tokens:
                    flag = _FLAG_TOKEN.match(token)
                    if flag and flag.group(1) not in shape.flags[scope]:
                        findings.append(f"{rel}:{line}: `{scope}` has no flag {flag.group(1)}")
    return findings


def unknown_bare_flags(rel: str, text: str, shape: Surface) -> list[str]:
    """An inline span that is a flag on its own must be some binary's flag."""
    known = {flag for flags in shape.flags.values() for flag in flags}
    findings: list[str] = []
    for line, code in code_fragments(text):
        flag = re.match(r"^(--[a-z][a-z0-9-]*)(?:[ =].*)?$", code)
        if flag and flag.group(1) not in known:
            findings.append(f"{rel}:{line}: no DireWolf binary has {flag.group(1)}")
    return findings


def unknown_make_targets(docs: Mapping[str, str], makefile: str) -> list[str]:
    """Every `make <target>` names a target; a pattern (`sandbox-*-evidence`)
    must match at least one."""
    targets = frozenset(re.findall(r"^([a-z0-9][a-z0-9-]*):", makefile, re.M))
    findings: list[str] = []
    for rel, text in docs.items():
        for line, code in code_fragments(text):
            for target in re.findall(r"(?<![\w-])make[ \t]+([a-z0-9][a-z0-9*-]*)", code):
                if not fnmatch.filter(targets, target):
                    findings.append(f"{rel}:{line}: no make target {target}")
    return findings


def cli_commands_unnamed(readme: str, shape: Surface) -> list[str]:
    """Every sentence of the README that says what `direwolf` supports names
    every command it has, and there is such a sentence."""
    advertised = sorted(shape.commands["direwolf"] - {"help", "version"})
    claims = re.findall(r"`direwolf` supports ([^.;]+)", _flat(readme))
    findings = [] if claims else ["README.md never says what `direwolf` supports"]
    for claim in claims:
        findings.extend(
            f"README.md: `direwolf` supports {claim!r} -- without `{command}`"
            for command in advertised
            if f"`{command}`" not in claim
        )
    return findings


# --- milestones ---------------------------------------------------------------------

_COMPLETE = re.compile(
    r"^#{3,4} (M\d+(?:\.\d+)?[a-z]?) · [^\n]*?— \*\*COMPLETE\*\* \((\d{4}-\d{2}-\d{2})", re.M
)
_TOP = re.compile(r"^M\d+(?:\.\d+)?$")


def roadmap_complete(roadmap: str) -> dict[str, str]:
    return dict(_COMPLETE.findall(roadmap))


def _number(milestone: str) -> float:
    return float(milestone[1:])


def latest_complete(roadmap: str) -> str:
    return max((m for m in roadmap_complete(roadmap) if _TOP.match(m)), key=_number)


def build_order(roadmap: str) -> tuple[str, list[str]]:
    match = re.search(r"\*\*Build order after (M[\d.]+) \([^)]*\):\*\* (.+?)\.\s", roadmap)
    assert match, "the roadmap states its build order"
    return match.group(1), [step.strip() for step in match.group(2).split("→")]


def milestone_disagreements(readme: str, roadmap: str) -> list[str]:
    complete = roadmap_complete(roadmap)
    latest = latest_complete(roadmap)
    findings: list[str] = []
    rows = re.findall(r"^\| (M\d+(?:\.\d+)?) · [^|]*\| ([^|]*)\| ([^|]*)\|", readme, re.M)
    listed = {m for m, status, _ in rows if "**COMPLETE**" in status}
    for milestone, status, date in rows:
        if "**COMPLETE**" in status:
            if complete.get(milestone) != date.strip():
                roadmap_date = complete.get(milestone)
                findings.append(
                    f"README: {milestone} COMPLETE {date.strip()}, roadmap {roadmap_date}"
                )
        elif milestone in complete:
            findings.append(f"README: {milestone} is {status.strip()}, roadmap COMPLETE")
    findings.extend(
        f"README: no COMPLETE row for {m}" for m in complete if _TOP.match(m) and m not in listed
    )
    badge = re.search(r"milestone-(M[\d.]+)%20complete", readme)
    if not badge or badge.group(1) != latest:
        findings.append(f"README badge says {badge and badge.group(1)}, roadmap {latest}")
    said = re.search(r"\*\*M1\u2013(M[\d.]+) are complete\.\*\*", readme)
    if not said or said.group(1) != latest:
        findings.append(f"README says M1{DASH}{said and said.group(1)} complete, roadmap {latest}")
    after, order = build_order(roadmap)
    if after != latest:
        findings.append(f"roadmap's build order is after {after}, its latest COMPLETE {latest}")
    nexts = [m for m, status, _ in rows if "next" in status]
    if nexts != [order[0]]:
        findings.append(f"README marks {nexts} next, the roadmap's order starts {order[0]}")
    for milestone, status, _ in rows:
        planned = re.search(r"after (M[\d.]+)", status)
        if (
            planned
            and milestone in order
            and planned.group(1) in order
            and order.index(milestone) <= order.index(planned.group(1))
        ):
            findings.append(f"README: {milestone} {status.strip()}, roadmap order {order}")
    return findings


def usage_claims(usages: Mapping[str, str], roadmap: str) -> list[str]:
    """No usage text calls a complete milestone in progress, or says which
    milestone the project is at unless it is the latest complete one."""
    complete, latest = roadmap_complete(roadmap), latest_complete(roadmap)
    findings: list[str] = []
    for name, text in usages.items():
        flat = _flat(text)
        for match in re.finditer(r"\b(M\d+(?:\.\d+)?[a-z]?)\b[^.;]{0,40}?\bin progress\b", flat):
            if match.group(1) in complete:
                findings.append(f"{name}: {match.group(1)} called in progress; it is COMPLETE")
        for match in re.finditer(r"\bat milestone (M[\d.]+)", flat):
            if match.group(1) != latest:
                findings.append(f"{name}: says it is at {match.group(1)}; latest COMPLETE {latest}")
    return findings


def _deps(roadmap: str, milestone: str) -> list[str]:
    match = re.search(
        rf"^#{{3,4}} {re.escape(milestone)} · [^\n]*\n\*\*Deps:\*\* ([^.]*)\.", roadmap, re.M
    )
    assert match, milestone
    return re.findall(r"M\d+[a-z]?(?:\u2013M\d+)?", match.group(1))


def tree_note_disagreements(roadmap: str) -> list[str]:
    note = re.search(r"line, the line decides -- (.+?) -- and", _flat(roadmap))
    if not note:
        return ["the roadmap's note on its tree is missing"]
    findings: list[str] = []
    for pair in note.group(1).split("; "):
        milestone, _, deps = pair.partition(": ")
        if sorted(deps.split(", ")) != sorted(_deps(roadmap, milestone)):
            findings.append(f"tree note {milestone}: {deps}; Deps: {_deps(roadmap, milestone)}")
    return findings


# --- records --------------------------------------------------------------------------

_STATUS = re.compile(r"^\*\*Status:\*\* (.*)$", re.M)


def adr_status_lines(read: Callable[[str], str] = _read) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for path in sorted((REPO_ROOT / "docs" / "adr").glob("[0-9][0-9][0-9][0-9]-*.md")):
        status = _STATUS.search(read(f"docs/adr/{path.name}"))
        assert status, path.name
        statuses[path.name[:4]] = status.group(1)
    return statuses


def adr_kind(status: str) -> str:
    if status.startswith("Accepted"):
        return "accepted"
    if "Superseded" in status:
        return "superseded"
    if status.startswith("Proposed"):
        return "proposed"
    return "unknown"


def _expand(numbers: str) -> list[str]:
    out: list[str] = []
    for item in numbers.split(", "):
        first, _, last = item.partition(DASH)
        out.extend(f"{n:04d}" for n in range(int(first), int(last or first) + 1))
    return out


_ADR_SENTENCE = re.compile(
    r"(\d+) architecture decision records \((\d{4})\u2013(\d{4})\): (\d+) accepted, (\d+) "
    r"superseded and kept as history \(([^)]*)\), and (\d+) Proposed \(([^)]*)\)"
)


def adr_count_disagreements(readme: str, statuses: Mapping[str, str]) -> list[str]:
    said = _ADR_SENTENCE.search(_flat(readme))
    if not said:
        return ["README.md: the sentence counting the decision records is missing"]
    total, first, last, accepted, superseded, s_list, proposed, p_list = said.groups()
    kinds: dict[str, list[str]] = {}
    for number, status in sorted(statuses.items()):
        kinds.setdefault(adr_kind(status), []).append(number)
    expected = {
        "total": (int(total), len(statuses)),
        "first": (first, min(statuses)),
        "last": (last, max(statuses)),
        "accepted": (int(accepted), len(kinds.get("accepted", []))),
        "superseded": (int(superseded), len(kinds.get("superseded", []))),
        "superseded list": (_expand(s_list), kinds.get("superseded", [])),
        "proposed": (int(proposed), len(kinds.get("proposed", []))),
        "proposed list": (_expand(p_list), kinds.get("proposed", [])),
        "unknown": ([], kinds.get("unknown", [])),
    }
    return [
        f"README.md: {what} says {said_value}, docs/adr/ has {actual}"
        for what, (said_value, actual) in expected.items()
        if said_value != actual
    ]


_LEDGER_ROW = re.compile(r"^\| (F-\d\d) \|[^|]*\|([^|]*)\| (OBSERVED|NOT EXERCISED|n/a) \|", re.M)


def _index_row(index: str, number: str) -> str:
    match = re.search(rf"^\| \[{number}\]\(.*$", index, re.M)
    return match.group(0) if match else ""


def ledger_disagreements(
    ledger: str, statuses: Mapping[str, str], index: str, roadmap: str
) -> list[str]:
    """The pre-M6 ledger, each record's status line, its index row and the
    roadmap's note say the same about hosted evidence."""
    findings: list[str] = []
    rows = _LEDGER_ROW.findall(ledger)
    if not rows:
        return ["PRE_M6_REMEDIATION.md: no ledger rows"]
    linked = set(re.findall(r"adr/(\d{4})-", ledger))
    for number, status in statuses.items():
        if adr_kind(status) == "proposed" and number >= "0060" and number not in linked:
            findings.append(f"ADR-{number} is Proposed and not in the pre-M6 ledger")
    note = re.search(r"\*\*Pre-M6 security remediation .*?until accepted\.", roadmap, re.S)
    sentences = re.split(r"(?<=\.)\s", _flat(note.group(0))) if note else []
    if not note:
        findings.append("ROADMAP.md: the pre-M6 note is missing")
    elif "PRE_M6_REMEDIATION.md" not in note.group(0):
        findings.append("ROADMAP.md: the pre-M6 note does not link the ledger")
    for finding, record, hosted in rows:
        for number in re.findall(r"adr/(\d{4})-", record):
            status, row = statuses.get(number, ""), _index_row(index, number)
            if hosted == "OBSERVED":
                for where, text in (("status line", status), ("index row", row)):
                    if re.search(r"pending", text, re.I):
                        findings.append(f"{finding}: ADR-{number}'s {where} says pending")
            if hosted == "NOT EXERCISED":
                for where, text in (("status line", status), ("index row", row)):
                    if "NOT EXERCISED" not in text:
                        findings.append(f"{finding}: ADR-{number}'s {where} hides NOT EXERCISED")
        if hosted == "NOT EXERCISED":
            for sentence in sentences:
                if re.search(rf"\b{finding}\b", sentence) and "NOT EXERCISED" not in sentence:
                    findings.append(f"ROADMAP.md: {finding} named without NOT EXERCISED")
    return findings


def spec_sections_without_as_built(spec: str, shape: Surface) -> list[str]:
    """PRODUCT_SPEC.md is the target: it says so at the top, and every section
    that shows a command the CLI does not have says what exists instead."""
    findings: list[str] = []
    head = "\n".join(spec.splitlines()[:12])
    if "OPERATIONS.md" not in head or "not the build" not in head:
        findings.append("PRODUCT_SPEC.md: no as-built banner linking OPERATIONS.md")
    for section in re.split(r"^(?=## )", spec, flags=re.M):
        title = section.splitlines()[0] if section else ""
        unbuilt = sorted(
            {
                word
                for _, code in code_fragments(section)
                for word in re.findall(r"(?<![\w./-])direwolf[ \t]+([a-z][a-z-]*)", code)
                if word not in shape.commands["direwolf"]
            }
        )
        if unbuilt and "**As built" not in section:
            findings.append(f"PRODUCT_SPEC.md {title!r}: shows {unbuilt} with no As built note")
    return findings


# --- the repository holds ------------------------------------------------------------


def _docs(names: Iterable[str] = AS_BUILT_DOCS) -> dict[str, str]:
    return {name: _read(name) for name in names}


def test_the_usage_texts_are_read_from_source_and_agree_with_dispatch() -> None:
    usages = usage_texts()
    shape = the_surface()
    assert shape.commands["direwolf"] == {"doctor", "models", "help", "version"}
    listed = set(re.findall(r"^    ([a-z]+)\s{2,}", usages["direwolf"], re.M))
    assert listed == shape.commands["direwolf"] - {"help", "version"}, listed
    assert shape.commands["direwolf models"] == {
        "status",
        "inspect",
        "import",
        "list",
        "verify",
        "remove",
        "recommend",
    }
    assert shape.commands["dwkd-authority"] == {"serve", "verify-audit"}
    dispatched = set(
        re.findall(r'Some\("([a-z][a-z-]*)"\)', _read("crates/dwkd-authority/src/main.rs"))
    )
    assert dispatched == shape.commands["dwkd-authority"], dispatched
    assert shape.commands["dwkd-broker"] == {"serve"}
    for flag in ("--egress-allowlist", "--path-anchor", "--approver-uid", "--sandbox-config"):
        assert flag in shape.flags["dwkd-authority"], flag
    for flag in ("--authority-uid", "--require-lsm", "--allow-evidence-trust"):
        assert flag in shape.flags["dwkd-broker"], flag
    assert "--library" in shape.flags["direwolf models"]


def test_every_command_and_flag_an_as_built_document_shows_exists() -> None:
    assert stale_commands(_docs(), the_surface()) == []


def test_the_operator_guide_names_only_real_flags() -> None:
    assert (
        unknown_bare_flags("docs/OPERATIONS.md", _read("docs/OPERATIONS.md"), the_surface()) == []
    )


def test_every_make_target_an_as_built_document_shows_exists() -> None:
    assert unknown_make_targets(_docs(), _read("Makefile")) == []


def test_the_readme_names_every_cli_command() -> None:
    assert cli_commands_unnamed(_read("README.md"), the_surface()) == []


def test_the_readme_milestones_agree_with_the_roadmap() -> None:
    assert milestone_disagreements(_read("README.md"), _read("docs/ROADMAP.md")) == []


def test_no_usage_text_calls_a_complete_milestone_in_progress() -> None:
    assert usage_claims(usage_texts(), _read("docs/ROADMAP.md")) == []


def test_the_roadmap_tree_note_agrees_with_each_deps_line() -> None:
    assert tree_note_disagreements(_read("docs/ROADMAP.md")) == []


def test_the_readme_counts_the_decision_records_as_they_are() -> None:
    assert adr_count_disagreements(_read("README.md"), adr_status_lines()) == []


def test_the_pre_m6_ledger_records_and_roadmap_agree() -> None:
    assert (
        ledger_disagreements(
            _read("docs/PRE_M6_REMEDIATION.md"),
            adr_status_lines(),
            _read("docs/adr/README.md"),
            _read("docs/ROADMAP.md"),
        )
        == []
    )


def test_the_product_spec_says_where_it_is_not_the_build() -> None:
    assert spec_sections_without_as_built(_read("docs/PRODUCT_SPEC.md"), the_surface()) == []


# --- each check fails on a broken fixture ---------------------------------------


def test_a_command_or_flag_that_does_not_exist_is_found() -> None:
    ops = _read("docs/OPERATIONS.md")
    shape = the_surface()
    for old, new in (
        (
            "`dwkd-authority serve --allow-authority-uid`",
            "`dwkd-authority serve --allow-everything`",
        ),
        ("direwolf models verify --library", "direwolf models fetch --library"),
        ("dwkd-broker serve --socket /run", "dwkd-broker start --socket /run"),
        (
            "  --egress-allowlist /etc/direwolf/egress.toml \\",
            "  --egress-allowed /etc/direwolf/egress.toml \\",
        ),
    ):
        broken = {"docs/OPERATIONS.md": _broken(ops, old, new)}
        assert stale_commands(broken, shape), new
    chat = {"README.md": "Run `direwolf chat coder` to start."}
    assert stale_commands(chat, shape) == ["README.md:1: `direwolf chat` does not exist"]


def test_a_bare_flag_no_binary_has_is_found() -> None:
    ops = _broken(
        _read("docs/OPERATIONS.md"), "`--allow-shared-broker-uid`", "`--allow-shared-broker`"
    )
    assert unknown_bare_flags("docs/OPERATIONS.md", ops, the_surface()) == [
        f"docs/OPERATIONS.md:{_line_of(ops, '`--allow-shared-broker`')}: "
        "no DireWolf binary has --allow-shared-broker"
    ]


def _line_of(text: str, needle: str) -> int:
    return text[: text.index(needle)].count("\n") + 1


def test_a_make_target_that_does_not_exist_is_found() -> None:
    readme = _broken(_read("README.md"), "make check        #", "make checks       #")
    assert unknown_make_targets({"README.md": readme}, _read("Makefile")) != []


def test_a_readme_that_forgets_a_cli_command_is_found() -> None:
    # The README as it read before F-13: it named `doctor` alone.
    readme = _broken(
        _read("README.md"),
        "`direwolf` supports `--version`, `doctor` and `models`.\n",
        "`direwolf` supports `--version` and `doctor`.\n",
    )
    assert any("without `models`" in f for f in cli_commands_unnamed(readme, the_surface()))


def test_a_readme_milestone_that_disagrees_with_the_roadmap_is_found() -> None:
    readme, roadmap = _read("README.md"), _read("docs/ROADMAP.md")
    for old, new in (
        ("| ✅ **COMPLETE** | 2026-11-11 |", "| ✅ **COMPLETE** | 2026-11-12 |"),
        ("milestone-M5%20complete", "milestone-M4%20complete"),
        ("| M6 · Approvals and budgets | ⏳ next |", "| M6 · Approvals and budgets | ⏳ planned |"),
        ("| ⏳ planned, after M6 |", "| ⏳ planned, after M7 |"),
    ):
        assert milestone_disagreements(_broken(readme, old, new), roadmap), new
    reopened = _broken(
        roadmap, "### M5 · Sandbox — **COMPLETE**", "### M5 · Sandbox — **IN PROGRESS**"
    )
    assert milestone_disagreements(readme, reopened)


def test_a_usage_text_that_calls_a_complete_milestone_in_progress_is_found() -> None:
    roadmap = _read("docs/ROADMAP.md")
    # The broker's and the CLI's text as they read before F-13.
    old_broker = "a credential composed into its one request. M5d\n(in progress) - one workload"
    old_cli = "not implemented: DireWolf is at milestone M1, the repository foundation."
    assert usage_claims({"dwkd-broker": old_broker}, roadmap) == [
        "dwkd-broker: M5d called in progress; it is COMPLETE"
    ]
    assert usage_claims({"direwolf": old_cli}, roadmap) == [
        "direwolf: says it is at M1; latest COMPLETE M5"
    ]


def test_a_tree_note_that_disagrees_with_a_deps_line_is_found() -> None:
    roadmap = _broken(_read("docs/ROADMAP.md"), "M10: M4, M5, M9;", "M10: M4, M9;")
    assert tree_note_disagreements(roadmap) != []


def test_a_wrong_decision_record_count_is_found() -> None:
    readme, statuses = _read("README.md"), adr_status_lines()
    assert adr_count_disagreements(_broken(readme, "and 16 Proposed", "and 15 Proposed"), statuses)
    with_another = {**statuses, "0075": "Proposed · **Date:** 2026-11-22"}
    assert adr_count_disagreements(readme, with_another)


def test_a_ledger_a_record_or_the_roadmap_that_disagrees_is_found() -> None:
    ledger, statuses = _read("docs/PRE_M6_REMEDIATION.md"), adr_status_lines()
    index, roadmap = _read("docs/adr/README.md"), _read("docs/ROADMAP.md")
    pending = {**statuses, "0060": "Proposed · (built; its hosted evidence is pending)"}
    assert ledger_disagreements(ledger, pending, index, roadmap)
    hidden = {**statuses, "0074": "Proposed · (built; hosted evidence observed)"}
    assert ledger_disagreements(ledger, hidden, index, roadmap)
    claimed = _broken(
        roadmap, "F-18, F-19, and the TLS floor", "F-16, F-18, F-19, and the TLS floor"
    )
    assert ledger_disagreements(ledger, statuses, index, claimed) == [
        "ROADMAP.md: F-16 named without NOT EXERCISED"
    ]
    unlisted = _broken(ledger, "[ADR-0060](adr/0060-", "[the record](records/0060-")
    assert ledger_disagreements(unlisted, statuses, index, roadmap)


def test_a_product_spec_section_without_its_as_built_note_is_found() -> None:
    spec = _broken(
        _read("docs/PRODUCT_SPEC.md"),
        "**As built (2026-11-21).** No layered configuration",
        "No layered configuration",
    )
    found = spec_sections_without_as_built(spec, the_surface())
    assert len(found) == 1 and "## 7. Configuration" in found[0], found

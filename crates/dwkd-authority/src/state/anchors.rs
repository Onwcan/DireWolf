//! Host path anchors (F-12, [ADR-0066], Proposed): what `~`, `${DIREWOLF_HOME}`,
//! `${DIREWOLF_CONFIG}` and `${DIREWOLF_INSTALL}` stand for on the host, and
//! where each host path a policy names lies relative to a run's pinned
//! workspace root.
//!
//! # Why this exists
//!
//! Every path a live filesystem decision is about is a logical
//! `/workspace/...` path the resolver found beneath the pinned root
//! ([ADR-0042]). The shipped packs' hard denials name host places --
//! `~/.ssh`, `/etc/shadow`, the container sockets, DireWolf's own state --
//! which are spellings of no logical path. Before F-12 the anchored ones were
//! simply unresolved, so `deny-credential-paths` denied every read
//! (`UNRESOLVED_POLICY_INPUT`); and the absolute ones were compared with
//! `/workspace/...` by spelling, so they never matched -- a workspace root
//! bound at `/etc` exposed `/workspace/shadow`, hidden only because the
//! unresolved home anchor refused the read first.
//!
//! # What an anchor is
//!
//! Operator configuration, never a variable: no `HOME`, no shell, no runtime
//! value, no subject's word (ADR-0028). `serve --path-anchor` names each
//! directory; `serve` adds what the authority itself knows to be DireWolf's
//! -- its state directory, the directories of the configuration files it read,
//! the directory of its own executable. Each is checked at start
//! ([`resource::fs::check_anchor_directory`]): absolute, a directory, not a
//! symlink, searchable by the authority. `~` has no default: without an
//! operator's home, every `~/...` rule stays unresolved and denies.
//!
//! # Where a host path lies
//!
//! Before each decision, with no transaction open, every host path of the
//! active policy is walked on the host from `/` and related to the pinned
//! root by `(device, inode)` ([`PinnedRoot::relation_to`]); an anchor with
//! several directories is related through each, and the strictest answer
//! wins. The policy engine receives the answers as values
//! ([`HostPlacements`]); it never looks at the filesystem (TX004, TX011).
//!
//! [ADR-0042]: ../../../../../docs/adr/0042-m4a-canonical-filesystem-resolution.md
//! [ADR-0066]: ../../../../../docs/adr/0066-f12-host-path-anchors-are-placed-by-identity.md

use crate::policy::{CompiledPolicy, HostPlacement, HostPlacements, PathAnchor, RulePath};
use crate::resource::fs::{self as resource, HostRelation, PinnedRoot};

/// The host directories each host path anchor stands for: operator
/// configuration, checked at start (F-12).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostAnchors {
    /// `~`: the home directories whose credentials the packs protect. No
    /// default -- an unconfigured home leaves every `~/...` rule unresolved.
    pub home: Vec<String>,
    /// `${DIREWOLF_HOME}`: DireWolf's state.
    pub direwolf_home: Vec<String>,
    /// `${DIREWOLF_CONFIG}`: DireWolf's configuration.
    pub direwolf_config: Vec<String>,
    /// `${DIREWOLF_INSTALL}`: DireWolf's binaries.
    pub direwolf_install: Vec<String>,
}

impl HostAnchors {
    /// The directories `anchor` stands for: `/` for an absolute path, none
    /// for `${WORKSPACE}` (never a host anchor).
    #[must_use]
    pub fn directories(&self, anchor: PathAnchor) -> Vec<&str> {
        let list = match anchor {
            PathAnchor::Absolute => return vec!["/"],
            PathAnchor::Workspace => return Vec::new(),
            PathAnchor::Home => &self.home,
            PathAnchor::DirewolfHome => &self.direwolf_home,
            PathAnchor::DirewolfConfig => &self.direwolf_config,
            PathAnchor::DirewolfInstall => &self.direwolf_install,
        };
        list.iter().map(String::as_str).collect()
    }

    /// Every configured directory, with its anchor: what start checks.
    pub fn each(&self) -> impl Iterator<Item = (PathAnchor, &str)> {
        [
            (PathAnchor::Home, &self.home),
            (PathAnchor::DirewolfHome, &self.direwolf_home),
            (PathAnchor::DirewolfConfig, &self.direwolf_config),
            (PathAnchor::DirewolfInstall, &self.direwolf_install),
        ]
        .into_iter()
        .flat_map(|(anchor, list)| list.iter().map(move |dir| (anchor, dir.as_str())))
    }

    /// These, and what the authority itself knows to be DireWolf's: its own
    /// resolved state directory -- which holds `kernel.db` and so the policy
    /// revision in force -- under `${DIREWOLF_HOME}` and `${DIREWOLF_CONFIG}`,
    /// and its executable's directory under `${DIREWOLF_INSTALL}`. Never `~`:
    /// no fact the authority holds says whose home it is.
    #[must_use]
    pub fn with_own(&self, state_directory: &std::path::Path) -> Self {
        let mut all = self.clone();
        let add = |list: &mut Vec<String>, dir: Option<String>| {
            if let Some(dir) = dir
                && !list.contains(&dir)
            {
                list.push(dir);
            }
        };
        let state = state_directory.to_str().map(str::to_owned);
        add(&mut all.direwolf_home, state.clone());
        add(&mut all.direwolf_config, state);
        add(
            &mut all.direwolf_install,
            resource::own_executable_directory(),
        );
        all
    }

    /// Check every configured directory (start-up).
    ///
    /// **Linux only.** Elsewhere no root can be pinned and no host path is
    /// ever placed (ADR-0042 §11, ADR-0066): every filesystem call is refused
    /// before a placement would be made, and every rule naming a host path
    /// stays unplaced. There is nothing to check, so nothing is refused --
    /// a start off Linux must not fail on a resolver that does not exist.
    ///
    /// # Errors
    ///
    /// The first that is not an absolute directory the authority can search,
    /// named by its anchor and path -- the operator's own configuration.
    pub fn check(&self) -> Result<(), String> {
        if !cfg!(target_os = "linux") {
            return Ok(());
        }
        for (anchor, dir) in self.each() {
            resource::check_anchor_directory(dir)
                .map_err(|error| format!("path anchor {anchor} = {dir}: {error}"))?;
        }
        Ok(())
    }
}

/// The host location a rule path names under one of its anchor's directories.
fn location(directory: &str, path: &RulePath) -> String {
    let mut text = directory.trim_end_matches('/').to_owned();
    for segment in path.segments() {
        text.push('/');
        text.push_str(segment);
    }
    if text.is_empty() {
        text.push('/');
    }
    text
}

/// What one relation says to policy.
const fn placement(relation: HostRelation) -> HostPlacement {
    match relation {
        HostRelation::Disjoint => HostPlacement::Disjoint,
        HostRelation::Encloses => HostPlacement::Encloses,
        HostRelation::Inside => HostPlacement::InsideWorkspace,
        HostRelation::Unknown => HostPlacement::Unexamined,
    }
}

/// How strict an answer is, for combining an anchor's several directories:
/// a match beats a doubt, and a doubt beats "no match".
const fn strictness(placement: HostPlacement) -> u8 {
    match placement {
        HostPlacement::Disjoint => 0,
        HostPlacement::Unexamined => 1,
        HostPlacement::InsideWorkspace => 2,
        HostPlacement::Encloses => 3,
    }
}

/// Where every host path of `policy` lies relative to `root`, pinned through
/// `root_host_path`. A path whose anchor has no directory is left unplaced:
/// its rule is unresolved, and denies. Call with no transaction open.
#[must_use]
pub(super) fn place(
    root: &PinnedRoot,
    root_host_path: &str,
    policy: &CompiledPolicy,
    anchors: &HostAnchors,
) -> HostPlacements {
    let mut placements = HostPlacements::new();
    for path in policy.host_paths() {
        let found = anchors
            .directories(path.anchor())
            .into_iter()
            .map(|directory| {
                placement(root.relation_to(root_host_path, &location(directory, &path)))
            })
            .max_by_key(|found| strictness(*found));
        if let Some(found) = found {
            placements.insert(path, found);
        }
    }
    placements
}

#[cfg(test)]
mod tests {
    use super::{HostAnchors, location, placement, strictness};
    use crate::policy::{HostPlacement, LOGICAL_ROOT, PathAnchor, RulePath};
    use crate::resource::fs::{HostRelation, WORKSPACE_ANCHOR};

    fn rule(text: &str) -> RulePath {
        RulePath::parse(text).unwrap_or_else(|error| unreachable!("{text}: {error}"))
    }

    #[test]
    fn the_policy_and_the_resolver_name_the_logical_root_alike() {
        assert_eq!(LOGICAL_ROOT, WORKSPACE_ANCHOR);
    }

    #[test]
    fn a_rule_path_is_its_anchor_directory_and_then_its_segments() {
        assert_eq!(location("/home/alice", &rule("~/.ssh")), "/home/alice/.ssh");
        assert_eq!(
            location("/home/alice/", &rule("~/.config/gh")),
            "/home/alice/.config/gh"
        );
        assert_eq!(location("/", &rule("/etc/shadow")), "/etc/shadow");
        assert_eq!(location("/", &rule("/")), "/");
        assert_eq!(
            location("/var/lib/dw", &rule("${DIREWOLF_HOME}")),
            "/var/lib/dw"
        );
    }

    #[test]
    fn an_absolute_path_hangs_from_the_host_root_and_the_workspace_from_nothing() {
        let anchors = HostAnchors::default();
        assert_eq!(anchors.directories(PathAnchor::Absolute), vec!["/"]);
        assert!(anchors.directories(PathAnchor::Workspace).is_empty());
        // No configured home, no default one.
        assert!(anchors.directories(PathAnchor::Home).is_empty());
    }

    #[test]
    fn a_match_beats_a_doubt_and_a_doubt_beats_no_match() {
        let order = [
            HostRelation::Disjoint,
            HostRelation::Unknown,
            HostRelation::Inside,
            HostRelation::Encloses,
        ]
        .map(|relation| strictness(placement(relation)));
        assert!(
            order.windows(2).all(|pair| pair.first() < pair.last()),
            "{order:?}"
        );
        assert_eq!(
            placement(HostRelation::Inside),
            HostPlacement::InsideWorkspace
        );
        assert_eq!(placement(HostRelation::Unknown), HostPlacement::Unexamined);
    }

    /// A shipped pack, compiled.
    #[cfg(target_os = "linux")]
    fn pack(file: &str) -> crate::policy::CompiledPolicy {
        let Some((_, text)) = crate::policy::profiles::ALL
            .into_iter()
            .find(|(name, _)| *name == file)
        else {
            unreachable!("{file} ships")
        };
        let Ok(profile) = crate::policy::load(file, text) else {
            unreachable!("{file} loads")
        };
        let name = profile.name().clone();
        let Ok(policy) = crate::policy::compose(&name, &[profile]) else {
            unreachable!("{file} composes")
        };
        policy
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_workspace_root_at_the_host_root_holds_every_absolute_protection() {
        // The defect the unresolved home anchor hid: with the root bound at
        // `/`, `/workspace/etc/shadow` IS `/etc/shadow`. Placed on the host,
        // every absolute protection lies inside the workspace -- unevaluated,
        // so denied -- and the anchored ones, with nothing configured, stay
        // unplaced.
        let (root, _) = crate::resource::fs::PinnedRoot::install("/")
            .unwrap_or_else(|error| unreachable!("the host root pins: {error}"));
        let placed = super::place(&root, "/", &pack("balanced.toml"), &HostAnchors::default());
        for absolute in [
            "/etc/shadow",
            "/etc/sudoers",
            "/var/run/docker.sock",
            "/run/podman/podman.sock",
        ] {
            assert_eq!(
                placed.get(&rule(absolute)),
                Some(HostPlacement::InsideWorkspace),
                "{absolute}"
            );
        }
        for anchored in ["~/.ssh", "${DIREWOLF_HOME}", "${DIREWOLF_CONFIG}"] {
            assert_eq!(placed.get(&rule(anchored)), None, "{anchored}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_anchor_with_several_directories_is_as_strict_as_its_strictest() {
        let scratch = crate::scratch::Scratch::new("f12-place");
        let ws = scratch.path().join("ws");
        let elsewhere = scratch.path().join("alice");
        for dir in [&ws, &elsewhere] {
            std::fs::create_dir_all(dir).unwrap_or_else(|error| unreachable!("{error}"));
        }
        let text = |path: &std::path::Path| path.to_str().map(str::to_owned).unwrap_or_default();
        let (root, _) = crate::resource::fs::PinnedRoot::install(&text(&ws))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let policy = pack("power.toml");
        // One home beside the workspace: every `~` rule disjoint.
        let beside = HostAnchors {
            home: vec![text(&elsewhere)],
            ..HostAnchors::default()
        };
        let placed = super::place(&root, &text(&ws), &policy, &beside);
        assert_eq!(placed.get(&rule("~/.ssh")), Some(HostPlacement::Disjoint));
        // A second home that is the workspace: the rule is not evaluated.
        let both = HostAnchors {
            home: vec![text(&elsewhere), text(&ws)],
            ..HostAnchors::default()
        };
        let placed = super::place(&root, &text(&ws), &policy, &both);
        assert_eq!(
            placed.get(&rule("~/.ssh")),
            Some(HostPlacement::InsideWorkspace)
        );
        // And `${DIREWOLF_HOME}` naming the workspace itself encloses it.
        let state_in_ws = HostAnchors {
            direwolf_home: vec![text(&ws)],
            ..HostAnchors::default()
        };
        let placed = super::place(&root, &text(&ws), &policy, &state_in_ws);
        assert_eq!(
            placed.get(&rule("${DIREWOLF_HOME}")),
            Some(HostPlacement::Encloses)
        );
    }
}

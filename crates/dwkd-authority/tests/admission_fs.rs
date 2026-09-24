//! M4b admission of `fs.read` through the production M4a resolver
//! ([ADR-0043] §8): every concrete path a NEW declaration names — the request,
//! the agent profile, every active skill, the mode ceiling — means what the
//! filesystem beneath the session's pinned workspace root says it means, and
//! nothing else. A trusted stored grant is re-read without being resolved.
//!
//! Real files, a real `kernel.db`, the real resolver. The audit record of each
//! admission lists every concrete path with the resolver's answer — the
//! identity of the object it found, or the class of its refusal — which is how
//! these tests see that a grant came through the resolver and not the grammar.
//!
//! [ADR-0043]: ../../../docs/adr/0043-m4b-private-broker-channel-and-brokered-fs-read.md

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use dwk_proto as _;
use proptest as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;

mod state_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, symlink};
    use std::path::{Path, PathBuf};

    use dwk_proto::dwkp::DwkpBody;
    use dwk_proto::json::{Object, Value};
    use dwk_proto::wire::id::SessionId;
    use dwk_proto::wire::scalar::{Epoch, WithheldReason};
    use dwkd_authority::capability::{PrivacyClass, UnresolvedScope};
    use dwkd_authority::state::{
        Admission, CallerContext, Reply, SkillTrust, WithheldCause, WorkspaceId,
        WorkspaceSensitivity,
    };

    use super::state_support::{
        Harness, admit_msg, audit_records, balanced, int, profile, query_msg, session, skill,
    };

    fn evidence(case: &str, outcome: &str) {
        println!(
            "FS-EVIDENCE {{\"category\":\"admission\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
        );
    }

    const UNRESOLVED: WithheldCause =
        WithheldCause::NeedsCanonicalization(UnresolvedScope::CanonicalPath);

    /// The workspace on disk.
    ///
    /// ```text
    /// src/main.rs  src/lib/a.rs  docs/guide.md
    /// link -> src               (a symlink)
    /// kelvin/K  kelvin/\u{212A} (canonically equivalent names)
    /// ```
    fn tree(dir: &Path) -> PathBuf {
        let root = dir.join("ws");
        fs::create_dir_all(root.join("src/lib")).unwrap();
        fs::create_dir_all(root.join("docs")).unwrap();
        fs::create_dir_all(root.join("kelvin")).unwrap();
        fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();
        fs::write(root.join("src/lib/a.rs"), b"pub fn a() {}").unwrap();
        fs::write(root.join("docs/guide.md"), b"# guide").unwrap();
        fs::write(root.join("kelvin/K"), b"latin").unwrap();
        fs::write(root.join("kelvin/\u{212A}"), b"kelvin").unwrap();
        symlink(root.join("src"), root.join("link")).unwrap();
        root
    }

    /// What the run's terms declare.
    struct Terms<'a> {
        profile: &'a [&'a str],
        skills: &'a [(&'a str, &'a [&'a str])],
        ceiling: &'a [&'a str],
    }

    const WIDE: Terms<'static> = Terms {
        profile: &["fs.read:*", "model.call:*"],
        skills: &[],
        ceiling: &["fs.read:*", "model.call:*"],
    };

    struct Fx {
        h: Harness,
        root: PathBuf,
        caller: CallerContext,
        session: SessionId,
        epoch: Epoch,
        key: u64,
    }

    impl Fx {
        /// A harness whose `reader` profile, baseline skills and ceiling are
        /// `terms`; a workspace bound to a root (unless `bind` is false) and a
        /// session bound to it; a lease.
        fn new(tag: &str, terms: &Terms<'_>, bind: bool) -> Self {
            let mut config = balanced();
            config.ceiling = terms.ceiling.iter().map(|s| (*s).to_owned()).collect();
            let mut h = Harness::with_config(tag, config);
            let root = tree(h.dir.path());
            let session = session(1);
            {
                let mut operator = h.authority().operator();
                for (name, declared) in terms.skills {
                    operator
                        .install_skill(&skill(name, SkillTrust::UserTrusted, declared))
                        .unwrap();
                }
                let baseline: Vec<&str> = terms.skills.iter().map(|(n, _)| *n).collect();
                operator
                    .install_agent_profile(&profile(
                        "reader",
                        terms.profile,
                        &baseline,
                        PrivacyClass::Any,
                    ))
                    .unwrap();
                if bind {
                    let id = WorkspaceId::new("proj").unwrap();
                    operator
                        .install_workspace(&id, WorkspaceSensitivity::Private)
                        .unwrap();
                    operator
                        .install_workspace_root(&id, root.to_str().unwrap())
                        .unwrap();
                    operator.bind_session_workspace(&session, &id).unwrap();
                }
            }
            let caller = h.connect(1000);
            let epoch = h.lease(&caller, &session);
            Self {
                h,
                root,
                caller,
                session,
                epoch,
                key: 0,
            }
        }

        fn admit(&mut self, requested: &[&str]) -> Admission {
            self.key += 1;
            let msg = admit_msg(
                &self.session,
                self.epoch,
                &format!("k{}", self.key),
                "reader",
                &[],
                requested,
                self.key,
            );
            match self.h.authority().admit_run(&self.caller, &msg).unwrap() {
                Reply::Done(admission) => admission,
                Reply::Refused(reason) => panic!("refused: {reason:?}"),
            }
        }

        /// The latest admission's audit record.
        fn record(&self) -> Object {
            audit_records(&self.h.state(), "run.admitted")
                .pop()
                .expect("an admission record")
        }

        fn identity(&self, relative: &str) -> (String, String) {
            let meta = fs::symlink_metadata(self.root.join(relative)).unwrap();
            (meta.dev().to_string(), meta.ino().to_string())
        }
    }

    fn granted(admission: &Admission) -> Vec<String> {
        admission
            .granted()
            .iter()
            .map(|g| g.capability().to_canonical_string())
            .collect()
    }

    fn withheld(admission: &Admission) -> Vec<(String, WithheldCause)> {
        admission
            .withheld()
            .iter()
            .map(|w| (w.requested().as_str().to_owned(), w.cause()))
            .collect()
    }

    /// One `fs_paths` entry of an admission record.
    #[derive(Debug, PartialEq, Eq)]
    struct Answer {
        outcome: String,
        identity: Option<(String, String)>,
    }

    fn answers(record: &Object) -> Vec<(String, Answer)> {
        let Some(Value::Array(entries)) = record.get("fs_paths") else {
            panic!("an fs_paths list")
        };
        entries
            .iter()
            .map(|entry| {
                let Value::Object(entry) = entry else {
                    panic!("an entry")
                };
                let get = |k: &str| match entry.get(k) {
                    Some(Value::String(s)) => Some(s.clone()),
                    _ => None,
                };
                let identity = get("device").zip(get("inode"));
                (
                    get("path").unwrap(),
                    Answer {
                        outcome: get("outcome").unwrap(),
                        identity,
                    },
                )
            })
            .collect()
    }

    fn answer_for(record: &Object, path: &str) -> Answer {
        answers(record)
            .into_iter()
            .find(|(p, _)| p == path)
            .unwrap_or_else(|| panic!("{path} is not in the record"))
            .1
    }

    #[test]
    fn every_minted_concrete_grant_came_through_the_resolver() {
        // Every term names a concrete path; the request lies beneath all of
        // them. Granted -- and the record shows the resolver's identity for
        // every path, the request's own included.
        let terms = Terms {
            profile: &["fs.read:/workspace/src", "model.call:*"],
            skills: &[("lib-only", &["fs.read:/workspace/src/lib"])],
            ceiling: &["fs.read:/workspace", "model.call:*"],
        };
        let mut fx = Fx::new("adm-fs-through", &terms, true);
        let admission = fx.admit(&["fs.read:/workspace/src/lib/a.rs?max_bytes=64"]);
        assert_eq!(
            granted(&admission),
            ["fs.read:/workspace/src/lib/a.rs?max_bytes=64"]
        );
        assert!(withheld(&admission).is_empty());
        let record = fx.record();
        for (path, relative) in [
            ("/workspace", "."),
            ("/workspace/src", "src"),
            ("/workspace/src/lib", "src/lib"),
            ("/workspace/src/lib/a.rs", "src/lib/a.rs"),
        ] {
            assert_eq!(
                answer_for(&record, path),
                Answer {
                    outcome: "RESOLVED".to_owned(),
                    identity: Some(fx.identity(relative)),
                },
                "{path}"
            );
        }
        assert_eq!(int(&record, "fs_paths_total"), Some(4));
        assert_eq!(int(&record, "fs_paths_unresolved"), Some(0));
        evidence("grant-through-resolver", "resolved-identity-recorded");

        // The same terms, and a request whose spelling every term covers --
        // but which names nothing on disk. The grammar alone would grant it;
        // the resolver finds nothing, so it is withheld.
        let absent = fx.admit(&["fs.read:/workspace/src/lib/zzz.rs?max_bytes=64"]);
        assert!(granted(&absent).is_empty());
        assert_eq!(
            withheld(&absent),
            [(
                "fs.read:/workspace/src/lib/zzz.rs?max_bytes=64".to_owned(),
                UNRESOLVED
            )]
        );
        assert_eq!(
            answer_for(&fx.record(), "/workspace/src/lib/zzz.rs").outcome,
            "NOT_FOUND"
        );
        evidence("missing-concrete-scope", "withheld:NOT_FOUND");
    }

    #[test]
    fn a_requested_path_that_does_not_resolve_is_withheld_with_its_class() {
        let mut fx = Fx::new("adm-fs-request", &WIDE, true);
        let cases = [
            (
                "fs.read:/workspace/missing",
                "/workspace/missing",
                "NOT_FOUND",
            ),
            ("fs.read:/workspace/link", "/workspace/link", "SYMLINK"),
            (
                "fs.read:/workspace/link/main.rs",
                "/workspace/link/main.rs",
                "SYMLINK",
            ),
            (
                "fs.read:/workspace/kelvin/K",
                "/workspace/kelvin/K",
                "NORMALIZATION_AMBIGUITY",
            ),
            (
                "fs.read:/workspace/src/main.rs/x",
                "/workspace/src/main.rs/x",
                "NOT_A_DIRECTORY",
            ),
            (
                "fs.read:/workspace/../etc",
                "/workspace/../etc",
                "PATH_TRAVERSAL",
            ),
            (
                "fs.read:/etc/passwd",
                "/etc/passwd",
                "PATH_OUTSIDE_WORKSPACE",
            ),
            (
                "fs.read:/workspace//src",
                "/workspace//src",
                "PATH_NOT_CANONICAL",
            ),
        ];
        let mut requested: Vec<&str> = cases.iter().map(|(r, ..)| *r).collect();
        // The positive control, in the same admission.
        requested.push("fs.read:/workspace/src/main.rs");
        let admission = fx.admit(&requested);
        assert_eq!(granted(&admission), ["fs.read:/workspace/src/main.rs"]);
        let expected: Vec<(String, WithheldCause)> = cases
            .iter()
            .map(|(r, ..)| ((*r).to_owned(), UNRESOLVED))
            .collect();
        assert_eq!(withheld(&admission), expected);
        let record = fx.record();
        for (_, path, class) in cases {
            assert_eq!(answer_for(&record, path).outcome, class, "{path}");
            assert_eq!(answer_for(&record, path).identity, None, "{path}");
            // One case per path: two paths can share a class.
            let at = path
                .trim_start_matches("/workspace")
                .trim_start_matches('/')
                .replace('/', "-");
            evidence(
                &format!("request-{}-at-{at}", class.to_lowercase().replace('_', "-")),
                &format!("withheld:{class}"),
            );
        }
        assert_eq!(
            answer_for(&record, "/workspace/src/main.rs").identity,
            Some(fx.identity("src/main.rs"))
        );
        assert_eq!(
            int(&record, "fs_paths_unresolved"),
            Some(i64::try_from(cases.len()).unwrap())
        );
        // On the wire: UNRESOLVED_RESOURCE, which claims nothing about why.
        fx.key += 1;
        let msg = admit_msg(
            &fx.session,
            fx.epoch,
            &format!("k{}", fx.key),
            "reader",
            &[],
            &["fs.read:/workspace/missing"],
            fx.key,
        );
        let DwkpBody::RunGrant(grant) = fx.h.authority().dispatch(&fx.caller, &msg).unwrap() else {
            panic!("a RunGrant")
        };
        assert_eq!(
            grant.withheld.iter().map(|w| w.reason).collect::<Vec<_>>(),
            [WithheldReason::UnresolvedResource]
        );
    }

    #[test]
    fn a_replaced_root_resolves_nothing() {
        let mut fx = Fx::new("adm-fs-root", &WIDE, true);
        let before = fx.admit(&["fs.read:/workspace/src/main.rs"]);
        assert_eq!(granted(&before), ["fs.read:/workspace/src/main.rs"]);
        // The operator's directory is replaced by another with the same
        // contents at the same host path.
        let moved = fx.root.with_file_name("ws-old");
        fs::rename(&fx.root, &moved).unwrap();
        let again = tree(fx.h.dir.path());
        assert_eq!(again, fx.root);
        let after = fx.admit(&["fs.read:/workspace/src/main.rs", "fs.read:*"]);
        assert_eq!(
            granted(&after),
            ["fs.read:*"],
            "the wildcard names no object"
        );
        assert_eq!(
            withheld(&after),
            [("fs.read:/workspace/src/main.rs".to_owned(), UNRESOLVED)]
        );
        assert_eq!(
            answer_for(&fx.record(), "/workspace/src/main.rs").outcome,
            "ROOT_REPLACED"
        );
        evidence("root-replaced", "withheld:ROOT_REPLACED");
    }

    #[test]
    fn without_a_bound_root_no_concrete_path_is_granted() {
        let mut fx = Fx::new("adm-fs-unbound", &WIDE, false);
        let admission = fx.admit(&["fs.read:/workspace/src/main.rs", "fs.read:*"]);
        assert_eq!(granted(&admission), ["fs.read:*"]);
        assert_eq!(
            withheld(&admission),
            [("fs.read:/workspace/src/main.rs".to_owned(), UNRESOLVED)]
        );
        assert_eq!(
            answer_for(&fx.record(), "/workspace/src/main.rs").outcome,
            "WORKSPACE_UNBOUND"
        );
        evidence("workspace-unbound", "withheld:WORKSPACE_UNBOUND");
    }

    #[test]
    fn each_term_is_resolved_and_one_that_does_not_resolve_covers_nothing() {
        let request = "fs.read:/workspace/src/main.rs";
        // (term, terms, expected cause, the term's failing path, its class)
        let cases: [(&str, Terms<'_>, WithheldCause, &str, &str); 4] = [
            (
                "profile",
                Terms {
                    profile: &["fs.read:/workspace/link", "fs.read:/workspace/gone"],
                    skills: &[],
                    ceiling: &["fs.read:*"],
                },
                WithheldCause::NotInAgentProfile,
                "/workspace/link",
                "SYMLINK",
            ),
            (
                "skill",
                Terms {
                    profile: &["fs.read:/workspace"],
                    skills: &[("narrow", &["fs.read:/workspace/gone"])],
                    ceiling: &["fs.read:*"],
                },
                WithheldCause::NotInSkillSet,
                "/workspace/gone",
                "NOT_FOUND",
            ),
            (
                "ceiling",
                Terms {
                    profile: &["fs.read:/workspace"],
                    skills: &[],
                    ceiling: &["fs.read:/workspace/link", "model.call:*"],
                },
                WithheldCause::AboveProfileCeiling,
                "/workspace/link",
                "SYMLINK",
            ),
            (
                "ceiling-ambiguous",
                Terms {
                    profile: &["fs.read:/workspace"],
                    skills: &[],
                    ceiling: &["fs.read:/workspace/kelvin/K", "model.call:*"],
                },
                WithheldCause::AboveProfileCeiling,
                "/workspace/kelvin/K",
                "NORMALIZATION_AMBIGUITY",
            ),
        ];
        for (term, terms, cause, path, class) in cases {
            let mut fx = Fx::new(&format!("adm-fs-term-{term}"), &terms, true);
            let admission = fx.admit(&[request]);
            assert!(granted(&admission).is_empty(), "{term}");
            assert_eq!(
                withheld(&admission),
                [(request.to_owned(), cause)],
                "{term}"
            );
            let record = fx.record();
            assert_eq!(answer_for(&record, path).outcome, class, "{term}");
            // The request itself resolved: only the term failed.
            assert_eq!(
                answer_for(&record, "/workspace/src/main.rs").identity,
                Some(fx.identity("src/main.rs")),
                "{term}"
            );
            evidence(
                &format!("term-{term}-unresolved"),
                &format!("covers-nothing:{class}"),
            );
        }
        // Each term's concrete path, when it resolves, is the resolver's: the
        // record carries the identity of the directory each term names.
        let terms = Terms {
            profile: &["fs.read:/workspace/src"],
            skills: &[(
                "docs-and-src",
                &["fs.read:/workspace/src", "fs.read:/workspace/docs"],
            )],
            ceiling: &["fs.read:/workspace/src", "model.call:*"],
        };
        let mut fx = Fx::new("adm-fs-term-ok", &terms, true);
        assert_eq!(granted(&fx.admit(&[request])), [request]);
        let record = fx.record();
        assert_eq!(
            answer_for(&record, "/workspace/docs").identity,
            Some(fx.identity("docs")),
            "a skill member no request names is resolved all the same"
        );
        assert_eq!(
            answer_for(&record, "/workspace/src").identity,
            Some(fx.identity("src"))
        );
    }

    #[test]
    fn a_declaration_that_is_not_one_canonical_path_covers_nothing() {
        // Operator declarations can carry text the wire's capability pattern
        // never admits. A non-NFC spelling (a decomposed "é"), a traversal and
        // an empty component each cover nothing -- the resolver's grammar
        // refuses them before any lookup.
        let nfd = "fs.read:/workspace/cafe\u{301}";
        let terms = Terms {
            profile: &[
                nfd,
                "fs.read:/workspace/src/../docs",
                "fs.read:/workspace//docs",
            ],
            skills: &[],
            ceiling: &["fs.read:*"],
        };
        let mut fx = Fx::new("adm-fs-nfc", &terms, true);
        fs::create_dir_all(fx.root.join("cafe\u{301}")).unwrap();
        let admission = fx.admit(&["fs.read:/workspace/docs/guide.md"]);
        assert_eq!(
            withheld(&admission),
            [(
                "fs.read:/workspace/docs/guide.md".to_owned(),
                WithheldCause::NotInAgentProfile
            )]
        );
        let record = fx.record();
        for (path, class) in [
            ("/workspace/cafe\u{301}", "PATH_NOT_CANONICAL"),
            ("/workspace/src/../docs", "PATH_TRAVERSAL"),
            ("/workspace//docs", "PATH_NOT_CANONICAL"),
        ] {
            assert_eq!(answer_for(&record, path).outcome, class, "{path}");
        }
        evidence("non-nfc-declaration", "covers-nothing:PATH_NOT_CANONICAL");
    }

    #[test]
    fn a_stored_grant_is_rehydrated_not_resolved() {
        // A grant the authority resolved and stored is re-read from the store
        // by its canonical text: after the object is gone the run's authority
        // still reads back identically -- while a NEW declaration of the same
        // path, resolved now, is withheld.
        let mut fx = Fx::new("adm-fs-rehydrate", &WIDE, true);
        let admission = fx.admit(&["fs.read:/workspace/docs", "model.call:*"]);
        assert_eq!(
            granted(&admission),
            ["fs.read:/workspace/docs", "model.call:*"]
        );
        fs::remove_dir_all(fx.root.join("docs")).unwrap();
        let query = query_msg(&fx.session, admission.run_id(), fx.epoch, None);
        let DwkpBody::EffectiveAuthority(answer) =
            fx.h.authority().dispatch(&fx.caller, &query).unwrap()
        else {
            panic!("an answer")
        };
        let texts: Vec<&str> = answer
            .granted
            .iter()
            .map(|g| g.capability.as_str())
            .collect();
        assert_eq!(texts, ["fs.read:/workspace/docs", "model.call:*"]);
        let fresh = fx.admit(&["fs.read:/workspace/docs"]);
        assert_eq!(
            withheld(&fresh),
            [("fs.read:/workspace/docs".to_owned(), UNRESOLVED)]
        );
        evidence("stored-grant-rehydrated", "not-resolved");
    }
}

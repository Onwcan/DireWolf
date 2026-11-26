//! M6.1: the canonical approval binding ([ADR-0079], Proposed; it amends
//! [ADR-0021] on acceptance).
//!
//! An [`ApprovalBinding`] states exactly what a future approval would cover,
//! and `binding_hash = SHA256(JCS(binding))` names it. The object is built
//! here, in the state layer, from values the authority itself decided,
//! resolved or recorded -- a `REQUIRE_APPROVAL` decision and the canonical
//! action it was made on, a resolver's identities, the run's record, the
//! operator's sandbox and its measurement, a secret's current revision --
//! and from nothing a runtime says.
//!
//! # A description, not authority
//!
//! A binding is not a capability, a lease, an approval, a token, a standing
//! grant, a permit or a decision. Nothing reads one to allow anything:
//! computing a hash never turns a denial into an allowance. The approval
//! registry (M6.2, `approvals.rs`, ADR-0080) is its one consumer: it builds a
//! sandboxed launch's binding, stores a request's canonical bytes, and
//! compares a later launch's with them -- equality is one of its guards,
//! never an allowance by itself. This module writes nothing, crosses no
//! protocol and is audited nowhere; its other producers have no caller until
//! their routes' approvals do, which is said below rather than hidden behind
//! a call that does nothing. TX066 keeps it that way.
//!
//! # The canonical object
//!
//! Thirteen members, every one always present:
//!
//! | member | from |
//! |---|---|
//! | `schema` | [`SCHEMA`] |
//! | `verb` | the decided capability's verb |
//! | `resource_identity` | [`BoundResource`]: a file by device and inode, a name to create by its parent's identity, an executable by path and SHA-256, a host by name, port and pinned addresses, a credential by handle |
//! | `canonical_args` | [`BoundArguments`]: byte counts, a content digest, the checked argv in order, an HTTP request's method and digests |
//! | `workspace` | the run's workspace and its root as recorded |
//! | `environment_profile` | [`BoundEnvironment`]: the host, or the operator's sandbox and its measured assurance |
//! | `credential_handles` | [`BoundCredentials`]: each handle's current revision and its metadata digest |
//! | `agent` | the run's agent profile and its revision |
//! | `requester` | the run's subject, as the kernel reported it at admission |
//! | `scope` | [`BoundScope`]: the rule's scope kind and its resolved payload |
//! | `taint_level` | the run's taint as the store holds it |
//! | `privacy_class` | the decided capability's privacy constraint, or `null` |
//! | `obligations` | the decision's obligations, only where the route keeps every one |
//!
//! **Encoding** ([ADR-0032]): RFC 8785 through
//! [`dwk_proto::json::to_canonical_bytes`], the one canonicaliser; SHA-256
//! through the state layer's digest. **Every integer is a decimal string**
//! -- a device, an inode, a byte count, a revision, a port -- so no value
//! is ever an IEEE-754 double and none can round into another. **Every set**
//! is an array sorted by its members' canonical bytes, a duplicate refused;
//! an ordered value (argv) keeps its order. Every variant carries `kind`.
//! No Unicode normalisation is applied: a string is bound as it was decided.
//!
//! [ADR-0079]: ../../../../../docs/adr/0079-the-approval-binding-v1-what-it-binds-and-how-it-is-encoded.md
//! [ADR-0021]: ../../../../../docs/adr/0021-approval-binding-v2.md
//! [ADR-0032]: ../../../../../docs/adr/0032-wire-contract-framing-strict-json-and-jcs.md

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "M6.2 builds a sandboxed launch's binding; the other routes' producers join with their approvals"
    )
)]

use core::fmt;

use dwk_proto::brokerp::sandbox::{AssuranceLevel, NetworkTopology};
use dwk_proto::dwkp::netops::HttpMethod;
use dwk_proto::json::{self, Object, Value};
use dwk_proto::limits::{MAX_PROCESS_ARG_BYTES, MAX_PROCESS_ARGS, MAX_PROCESS_ARGV_BYTES};
use dwk_proto::wire::guard::Address;
use dwk_proto::wire::id::RunId;
use dwk_proto::wire::scalar::AgentProfileName;
use rusqlite::OptionalExtension as _;

use crate::capability::{
    Action, ArgvAllowlist, ExecutableIdentity, MethodSet, Namespace, PrivacyClass, Verb,
};
use crate::policy::{
    ApprovalScopeKind, CanonicalAction, Decision, Effect, Environment, Obligation, Obligations,
    TaintLevel,
};
use crate::resource::fs::{FileIdentity, RootFingerprint};
use crate::sandbox::{EnvironmentKind, Judgement, SandboxConfig};
use crate::secret::metadata::SecretHandle;

use super::Work;
use super::config::WorkspaceId;
use super::digest::{self, Sha256Hash};
use super::error::AuthorityError;
use super::identity::AuthenticatedSubject;
use super::secrets::Current;
use super::taint;

/// The schema member: version 1 of the field set and its interpretation. A
/// changed field set or meaning is a new string, never this one reread.
pub(crate) const SCHEMA: &str = "direwolf.approval.binding.v1";

/// The most members a set may hold: files, verbs, addresses, credentials.
/// [ADR-0074] refuses an answer of more than 64 addresses; the rest share
/// its bound.
///
/// [ADR-0074]: ../../../../../docs/adr/0074-f16-the-broker-resolves-the-decided-name-and-no-other.md
pub(crate) const MAX_SET_MEMBERS: usize = 64;

/// The largest canonical binding. Above every bounded input's worst case --
/// a 64 KiB argv escaped six bytes for one -- and far below memory.
pub(crate) const MAX_CANONICAL_BYTES: usize = 1 << 20;

/// The longest host name: RFC 1035's 253 characters.
const MAX_HOST_CHARS: usize = 253;

/// The longest leaf name: `NAME_MAX`.
const MAX_LEAF_BYTES: usize = 255;

/// The secret revision state a binding may name: configured, never revoked
/// or removed.
const CONFIGURED: &str = "CONFIGURED";

/// Why no binding was built. Each is a refusal, never a default: a binding
/// that cannot name everything it covers covers nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum BindingError {
    /// The decision is not a `REQUIRE_APPROVAL`, or names no approval shape.
    NotApprovable,
    /// The canonical action is not the one the decision was made on.
    ActionMismatch,
    /// The scope is not the rule's kind, or the action is not within it.
    ScopeMismatch,
    /// The resource identity does not fit the verb.
    ResourceMismatch,
    /// The arguments do not fit the verb.
    ArgumentsMismatch,
    /// The environment is not the one the action was decided in.
    EnvironmentMismatch,
    /// The sandbox's measurement does not make it usable.
    EnvironmentUnusable,
    /// The route does not keep every obligation the decision carries.
    ObligationUnenforceable,
    /// A credential is revoked, removed or not configured.
    CredentialUnavailable,
    /// The run is not known, or not active.
    RunUnavailable,
    /// A set names one member twice.
    DuplicateMember,
    /// A set that must name something names nothing.
    EmptySet,
    /// A set is past [`MAX_SET_MEMBERS`], or an argv past its bounds.
    TooManyMembers,
    /// The canonical binding is past [`MAX_CANONICAL_BYTES`].
    TooLarge,
    /// A name, host, port or revision is not one a binding can hold.
    Malformed,
}

impl BindingError {
    /// The stable spelling.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::NotApprovable => "NOT_APPROVABLE",
            Self::ActionMismatch => "ACTION_MISMATCH",
            Self::ScopeMismatch => "SCOPE_MISMATCH",
            Self::ResourceMismatch => "RESOURCE_MISMATCH",
            Self::ArgumentsMismatch => "ARGUMENTS_MISMATCH",
            Self::EnvironmentMismatch => "ENVIRONMENT_MISMATCH",
            Self::EnvironmentUnusable => "ENVIRONMENT_UNUSABLE",
            Self::ObligationUnenforceable => "OBLIGATION_UNENFORCEABLE",
            Self::CredentialUnavailable => "CREDENTIAL_UNAVAILABLE",
            Self::RunUnavailable => "RUN_UNAVAILABLE",
            Self::DuplicateMember => "DUPLICATE_MEMBER",
            Self::EmptySet => "EMPTY_SET",
            Self::TooManyMembers => "TOO_MANY_MEMBERS",
            Self::TooLarge => "TOO_LARGE",
            Self::Malformed => "MALFORMED",
        }
    }
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers: strings, decimal-string integers, tagged objects, sets.
// ---------------------------------------------------------------------------

fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

/// An unsigned integer: decimal, no sign, no leading zero.
fn unsigned(value: u64) -> Value {
    Value::String(value.to_string())
}

/// A signed integer: decimal, `-` only before a negative value.
fn signed(value: i64) -> Value {
    Value::String(value.to_string())
}

fn object(members: Vec<(&'static str, Value)>) -> Result<Value, BindingError> {
    let mut out = Object::new();
    for (key, value) in members {
        out.insert(key.to_owned(), value)
            .map_err(|_| BindingError::Malformed)?;
    }
    Ok(Value::Object(out))
}

/// An object with its variant's `kind`.
fn tagged(
    kind: &'static str,
    mut members: Vec<(&'static str, Value)>,
) -> Result<Value, BindingError> {
    members.push(("kind", text(kind)));
    object(members)
}

/// A set: members sorted by their canonical bytes, a duplicate refused.
fn set(members: Vec<Value>, required: bool) -> Result<Value, BindingError> {
    if members.len() > MAX_SET_MEMBERS {
        return Err(BindingError::TooManyMembers);
    }
    if required && members.is_empty() {
        return Err(BindingError::EmptySet);
    }
    let mut keyed: Vec<(Vec<u8>, Value)> = members
        .into_iter()
        .map(|member| (json::to_canonical_bytes(&member), member))
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    if keyed
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if a.0 == b.0))
    {
        return Err(BindingError::DuplicateMember);
    }
    Ok(Value::Array(
        keyed.into_iter().map(|(_, member)| member).collect(),
    ))
}

fn file(identity: FileIdentity) -> Result<Value, BindingError> {
    object(vec![
        ("device", unsigned(identity.device())),
        ("inode", unsigned(identity.inode())),
    ])
}

fn executable(identity: &ExecutableIdentity) -> Result<Value, BindingError> {
    object(vec![
        ("path", text(&identity.path().to_string())),
        ("sha256", text(&identity.digest().to_string())),
    ])
}

/// An address, one spelling per address: IPv4 dotted decimal, IPv6 as eight
/// four-digit lowercase groups, never compressed. A mapped IPv4 address is
/// IPv6 and stays distinct.
fn address(address: Address) -> String {
    match address {
        Address::V4([a, b, c, d]) => format!("{a}.{b}.{c}.{d}"),
        Address::V6(octets) => octets
            .chunks(2)
            .map(|pair| match pair {
                [high, low] => format!("{high:02x}{low:02x}"),
                _ => String::new(),
            })
            .collect::<Vec<_>>()
            .join(":"),
    }
}

fn port(port: u16) -> Value {
    unsigned(u64::from(port))
}

/// A decided host name: lowercase letters, digits, `-` and `.`, no empty
/// label at either end. An IP literal in brackets is not one, and refused.
fn host_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HOST_CHARS
        && !name.starts_with('.')
        && !name.ends_with('.')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

/// A name the resolver found vacant beneath a directory: one component.
fn leaf_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_LEAF_BYTES
        && name != "."
        && name != ".."
        && !name.bytes().any(|b| b == b'/' || b == 0)
}

fn revision(value: i64) -> Result<u64, BindingError> {
    u64::try_from(value)
        .ok()
        .filter(|r| *r >= 1)
        .ok_or(BindingError::Malformed)
}

// ---------------------------------------------------------------------------
// The members.
// ---------------------------------------------------------------------------

/// What an action is on: an object by its identity, never by its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundResource(Resource);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Resource {
    /// An existing object, as the resolver opened it.
    File(FileIdentity),
    /// A name to create: the directory that will hold it, and the name.
    Vacant { parent: FileIdentity, name: String },
    /// An executable, as the resolver hashed it or the manifest pins it.
    Executable(ExecutableIdentity),
    /// A host: the decided name, the port and the pinned addresses.
    Host(BoundHost),
    /// A credential, by handle; its revision is `credential_handles`'.
    Credential(SecretHandle),
}

impl BoundResource {
    /// An existing object, by the identity the resolver opened.
    pub(in crate::state) const fn file(identity: FileIdentity) -> Self {
        Self(Resource::File(identity))
    }

    /// A vacant name beneath `parent`.
    ///
    /// # Errors
    ///
    /// [`BindingError::Malformed`] for a name that is not one component.
    pub(in crate::state) fn vacant(parent: FileIdentity, name: &str) -> Result<Self, BindingError> {
        if !leaf_name(name) {
            return Err(BindingError::Malformed);
        }
        Ok(Self(Resource::Vacant {
            parent,
            name: name.to_owned(),
        }))
    }

    /// An executable identity, minted by the resolver or the manifest.
    pub(in crate::state) fn executable(identity: &ExecutableIdentity) -> Self {
        Self(Resource::Executable(identity.clone()))
    }

    /// A host, with its pinned addresses.
    pub(in crate::state) const fn host(host: BoundHost) -> Self {
        Self(Resource::Host(host))
    }

    /// A credential.
    pub(in crate::state) fn credential(handle: &SecretHandle) -> Self {
        Self(Resource::Credential(handle.clone()))
    }

    fn value(&self) -> Result<Value, BindingError> {
        match &self.0 {
            Resource::File(identity) => tagged(
                "file",
                vec![
                    ("device", unsigned(identity.device())),
                    ("inode", unsigned(identity.inode())),
                ],
            ),
            Resource::Vacant { parent, name } => tagged(
                "vacant",
                vec![("parent", file(*parent)?), ("name", text(name))],
            ),
            Resource::Executable(identity) => tagged(
                "executable",
                vec![
                    ("path", text(&identity.path().to_string())),
                    ("sha256", text(&identity.digest().to_string())),
                ],
            ),
            Resource::Host(host) => tagged("host", host.members()?),
            Resource::Credential(handle) => {
                tagged("credential", vec![("handle", text(handle.as_str()))])
            }
        }
    }
}

/// A host as a hop reaches it: the name policy decided, the port, and every
/// address the guard pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundHost {
    name: String,
    port: u16,
    addresses: Vec<Address>,
}

impl BoundHost {
    /// The decided name, its port and its pinned answer.
    ///
    /// # Errors
    ///
    /// [`BindingError::Malformed`] for a name that is not a decided host name
    /// or port zero; [`BindingError::EmptySet`] for no address;
    /// [`BindingError::TooManyMembers`] past [`MAX_SET_MEMBERS`]. A repeated
    /// address is refused when the binding is encoded.
    pub(in crate::state) fn pinned(
        name: &str,
        port: u16,
        addresses: &[Address],
    ) -> Result<Self, BindingError> {
        if !host_name(name) || port == 0 {
            return Err(BindingError::Malformed);
        }
        if addresses.is_empty() {
            return Err(BindingError::EmptySet);
        }
        if addresses.len() > MAX_SET_MEMBERS {
            return Err(BindingError::TooManyMembers);
        }
        // Held sorted, so one answer in two orders is one host; encoded
        // sorted by spelling, as every set is.
        let mut addresses = addresses.to_vec();
        addresses.sort_unstable();
        Ok(Self {
            name: name.to_owned(),
            port,
            addresses,
        })
    }

    fn members(&self) -> Result<Vec<(&'static str, Value)>, BindingError> {
        let addresses: Vec<Value> = self.addresses.iter().map(|a| text(&address(*a))).collect();
        Ok(vec![
            ("host", text(&self.name)),
            ("port", port(self.port)),
            ("addresses", set(addresses, true)?),
        ])
    }
}

/// What an action does to its resource, canonically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundArguments(Arguments);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Arguments {
    /// A filesystem action that moves no content, or reads a bound of it.
    Fs { byte_count: u64 },
    /// A filesystem action that writes this content.
    FsContent {
        byte_count: u64,
        content: Sha256Hash,
    },
    /// A process's arguments, checked, in order.
    Argv(Vec<String>),
    /// An HTTP request: the method, the URL as a digest (never its path or
    /// query, [ADR-0050] §13), and the body as a digest and a length.
    ///
    /// [ADR-0050]: ../../../../../docs/adr/0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md
    Http {
        method: HttpMethod,
        url: Sha256Hash,
        body_bytes: u64,
        body: Sha256Hash,
    },
    /// An action with no arguments (`secret.use`).
    None,
}

impl BoundArguments {
    /// A filesystem action's byte count.
    pub(in crate::state) const fn fs(byte_count: u64) -> Self {
        Self(Arguments::Fs { byte_count })
    }

    /// A filesystem write of `content`, bound by its SHA-256 and length.
    ///
    /// # Errors
    ///
    /// [`BindingError::TooLarge`] for a length no `u64` holds.
    pub(in crate::state) fn fs_content(content: &[u8]) -> Result<Self, BindingError> {
        let byte_count = u64::try_from(content.len()).map_err(|_| BindingError::TooLarge)?;
        Ok(Self(Arguments::FsContent {
            byte_count,
            content: digest::plain(content),
        }))
    }

    /// A process's checked arguments, in order.
    ///
    /// # Errors
    ///
    /// [`BindingError::TooManyMembers`] past DWKP's own argv bounds.
    pub(in crate::state) fn argv(args: &[&str]) -> Result<Self, BindingError> {
        let total: usize = args.iter().map(|a| a.len()).sum();
        if args.len() > MAX_PROCESS_ARGS
            || args.iter().any(|a| a.len() > MAX_PROCESS_ARG_BYTES)
            || total > MAX_PROCESS_ARGV_BYTES
        {
            return Err(BindingError::TooManyMembers);
        }
        Ok(Self(Arguments::Argv(
            args.iter().copied().map(str::to_owned).collect(),
        )))
    }

    /// An HTTP request: its method, its URL's digest as the hop computed it,
    /// and its body.
    ///
    /// # Errors
    ///
    /// [`BindingError::ArgumentsMismatch`] for a body on a method that
    /// carries none; [`BindingError::TooLarge`] for a length no `u64` holds.
    pub(in crate::state) fn http(
        method: HttpMethod,
        url_sha256: Sha256Hash,
        body: &[u8],
    ) -> Result<Self, BindingError> {
        if !method.permits_body() && !body.is_empty() {
            return Err(BindingError::ArgumentsMismatch);
        }
        let body_bytes = u64::try_from(body.len()).map_err(|_| BindingError::TooLarge)?;
        Ok(Self(Arguments::Http {
            method,
            url: url_sha256,
            body_bytes,
            body: digest::plain(body),
        }))
    }

    /// No arguments.
    pub(in crate::state) const fn none() -> Self {
        Self(Arguments::None)
    }

    fn value(&self) -> Result<Value, BindingError> {
        match &self.0 {
            Arguments::Fs { byte_count } => {
                tagged("fs", vec![("byte_count", unsigned(*byte_count))])
            }
            Arguments::FsContent {
                byte_count,
                content,
            } => tagged(
                "fs_content",
                vec![
                    ("byte_count", unsigned(*byte_count)),
                    ("content_sha256", text(&content.to_hex())),
                ],
            ),
            Arguments::Argv(args) => tagged(
                "argv",
                vec![(
                    "argv",
                    Value::Array(args.iter().map(|a| Value::String(a.clone())).collect()),
                )],
            ),
            Arguments::Http {
                method,
                url,
                body_bytes,
                body,
            } => tagged(
                "http",
                vec![
                    ("method", text(method.as_str())),
                    ("url_sha256", text(&url.to_hex())),
                    ("body_bytes", unsigned(*body_bytes)),
                    ("body_sha256", text(&body.to_hex())),
                ],
            ),
            Arguments::None => tagged("none", Vec::new()),
        }
    }
}

/// The run's workspace: its id and its root as recorded when it was
/// installed. A root replaced at the same path is another root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundWorkspace {
    id: WorkspaceId,
    root: RootFingerprint,
}

impl BoundWorkspace {
    /// The workspace and its recorded root.
    pub(in crate::state) const fn recorded(id: WorkspaceId, root: RootFingerprint) -> Self {
        Self { id, root }
    }

    fn value(&self) -> Result<Value, BindingError> {
        let birth = match self.root.birth() {
            Some(birth) => object(vec![
                ("seconds", signed(birth.seconds)),
                ("nanoseconds", unsigned(u64::from(birth.nanoseconds))),
            ])?,
            None => Value::Null,
        };
        object(vec![
            ("id", text(self.id.as_str())),
            (
                "root",
                object(vec![
                    ("device", unsigned(self.root.device())),
                    ("inode", unsigned(self.root.inode())),
                    ("birth", birth),
                ])?,
            ),
        ])
    }
}

/// Where the action would run: the host, or the operator's sandbox as
/// configured and as measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundEnvironment(Placement);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Placement {
    Host,
    Sandbox(Box<SandboxIdentity>),
}

/// A sandbox's identity: what the operator configured, by content where it
/// has content, and the assurance its measurement earned.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SandboxIdentity {
    runtime: String,
    socket: String,
    image: String,
    probe_sha256: String,
    topology: NetworkTopology,
    relay_sha256: Option<String>,
    assurance: AssuranceLevel,
}

impl BoundEnvironment {
    /// The host.
    pub(in crate::state) const fn host() -> Self {
        Self(Placement::Host)
    }

    /// The operator's sandbox, as `judgement` measured an environment of it.
    ///
    /// # Errors
    ///
    /// [`BindingError::EnvironmentUnusable`] for a measurement that does not
    /// make the environment usable: a name is never taken for a posture.
    pub(in crate::state) fn sandbox(
        config: &SandboxConfig,
        judgement: &Judgement,
    ) -> Result<Self, BindingError> {
        if !judgement.usable(EnvironmentKind::Oci) {
            return Err(BindingError::EnvironmentUnusable);
        }
        Ok(Self(Placement::Sandbox(Box::new(SandboxIdentity {
            runtime: config.runtime().to_owned(),
            socket: config.socket().as_str().to_owned(),
            image: config.image().as_str().to_owned(),
            probe_sha256: config.probe_sha256().as_str().to_owned(),
            topology: config.topology(),
            relay_sha256: config
                .egress()
                .map(|e| e.relay_sha256().as_str().to_owned()),
            assurance: judgement.effective.0,
        }))))
    }

    const fn environment(&self) -> Environment {
        match self.0 {
            Placement::Host => Environment::Host,
            Placement::Sandbox(_) => Environment::Sandbox,
        }
    }

    fn value(&self) -> Result<Value, BindingError> {
        match &self.0 {
            Placement::Host => tagged("host", Vec::new()),
            Placement::Sandbox(sandbox) => tagged(
                "sandbox",
                vec![
                    ("runtime", text(&sandbox.runtime)),
                    ("socket", text(&sandbox.socket)),
                    ("image", text(&sandbox.image)),
                    ("probe_sha256", text(&sandbox.probe_sha256)),
                    ("topology", text(sandbox.topology.as_str())),
                    (
                        "relay_sha256",
                        sandbox.relay_sha256.as_deref().map_or(Value::Null, text),
                    ),
                    ("assurance", text(sandbox.assurance.as_str())),
                ],
            ),
        }
    }
}

/// The credentials an action would use, each at its current revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundCredentials(Vec<BoundCredential>);

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundCredential {
    handle: SecretHandle,
    revision: u64,
    metadata: Sha256Hash,
}

impl BoundCredentials {
    /// None.
    pub(in crate::state) const fn none() -> Self {
        Self(Vec::new())
    }

    /// Each handle at the revision the store holds as current.
    ///
    /// # Errors
    ///
    /// [`BindingError::CredentialUnavailable`] for a revision that is not
    /// `CONFIGURED`; [`BindingError::Malformed`] for a revision or digest a
    /// store could not have written; [`BindingError::DuplicateMember`] for a
    /// handle named twice; [`BindingError::TooManyMembers`] past the bound.
    pub(in crate::state) fn current(
        members: &[(&SecretHandle, &Current)],
    ) -> Result<Self, BindingError> {
        let mut out = Vec::with_capacity(members.len());
        for (handle, current) in members {
            if current.state != CONFIGURED {
                return Err(BindingError::CredentialUnavailable);
            }
            out.push(BoundCredential {
                handle: (*handle).clone(),
                revision: revision(current.revision)?,
                metadata: Sha256Hash::from_hex(current.metadata_sha256())
                    .ok_or(BindingError::Malformed)?,
            });
        }
        Self::checked(out)
    }

    fn checked(mut members: Vec<BoundCredential>) -> Result<Self, BindingError> {
        if members.len() > MAX_SET_MEMBERS {
            return Err(BindingError::TooManyMembers);
        }
        members.sort_by(|a, b| a.handle.cmp(&b.handle));
        if members
            .windows(2)
            .any(|pair| matches!(pair, [a, b] if a.handle == b.handle))
        {
            return Err(BindingError::DuplicateMember);
        }
        Ok(Self(members))
    }

    fn holds(&self, handle: &SecretHandle) -> bool {
        self.0.iter().any(|c| &c.handle == handle)
    }

    fn value(&self) -> Result<Value, BindingError> {
        let members = self
            .0
            .iter()
            .map(|c| {
                object(vec![
                    ("handle", text(c.handle.as_str())),
                    ("revision", unsigned(c.revision)),
                    ("metadata_sha256", text(&c.metadata.to_hex())),
                ])
            })
            .collect::<Result<Vec<_>, _>>()?;
        set(members, false)
    }
}

/// The agent a run was admitted under: its profile and the revision the run
/// record holds. Not an agent id: none exists before the agent loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundAgent {
    profile: AgentProfileName,
    revision: u64,
}

impl BoundAgent {
    /// The profile and revision a run record names.
    ///
    /// # Errors
    ///
    /// [`BindingError::Malformed`] for a name or revision a store could not
    /// have written.
    pub(in crate::state) fn recorded(profile: &str, revision: i64) -> Result<Self, BindingError> {
        Ok(Self {
            profile: AgentProfileName::new(profile).ok_or(BindingError::Malformed)?,
            revision: self::revision(revision)?,
        })
    }

    fn value(&self) -> Result<Value, BindingError> {
        object(vec![
            ("profile", text(self.profile.as_str())),
            ("revision", unsigned(self.revision)),
        ])
    }
}

/// The breadth a rule offers, with the identities that make it concrete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundScope(Scope);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Scope {
    ExactAction,
    PathSet {
        verb: Verb,
        files: Vec<FileIdentity>,
    },
    PathSubtree {
        root: FileIdentity,
        verbs: Vec<Verb>,
    },
    ExecutableAndArgv {
        executable: ExecutableIdentity,
        argv: ArgvAllowlist,
    },
    HostAndMethods {
        host: BoundHost,
        methods: MethodSet,
    },
    CredentialUse {
        handle: SecretHandle,
        host: String,
        port: u16,
    },
}

impl BoundScope {
    /// This action, and nothing else.
    pub(in crate::state) const fn exact_action() -> Self {
        Self(Scope::ExactAction)
    }

    /// One verb on a set of resolved files.
    ///
    /// # Errors
    ///
    /// [`BindingError::EmptySet`], [`BindingError::TooManyMembers`]; a file
    /// named twice is refused when the binding is encoded.
    pub(in crate::state) fn path_set(
        verb: Verb,
        files: &[FileIdentity],
    ) -> Result<Self, BindingError> {
        bounded(files.len(), true)?;
        Ok(Self(Scope::PathSet {
            verb,
            files: files.to_vec(),
        }))
    }

    /// Verbs beneath a directory, bound to the directory's identity.
    ///
    /// # Errors
    ///
    /// As [`Self::path_set`], for the verbs.
    pub(in crate::state) fn path_subtree(
        root: FileIdentity,
        verbs: &[Verb],
    ) -> Result<Self, BindingError> {
        bounded(verbs.len(), true)?;
        Ok(Self(Scope::PathSubtree {
            root,
            verbs: verbs.to_vec(),
        }))
    }

    /// An executable with the argv tokens a rule allows.
    pub(in crate::state) fn executable_and_argv(
        executable: &ExecutableIdentity,
        argv: &ArgvAllowlist,
    ) -> Self {
        Self(Scope::ExecutableAndArgv {
            executable: executable.clone(),
            argv: argv.clone(),
        })
    }

    /// A pinned host with a method set.
    pub(in crate::state) const fn host_and_methods(host: BoundHost, methods: MethodSet) -> Self {
        Self(Scope::HostAndMethods { host, methods })
    }

    /// A credential against one upstream.
    ///
    /// # Errors
    ///
    /// [`BindingError::Malformed`] for a host that is not a decided name, or
    /// port zero.
    pub(in crate::state) fn credential_use(
        handle: &SecretHandle,
        host: &str,
        port: u16,
    ) -> Result<Self, BindingError> {
        if !host_name(host) || port == 0 {
            return Err(BindingError::Malformed);
        }
        Ok(Self(Scope::CredentialUse {
            handle: handle.clone(),
            host: host.to_owned(),
            port,
        }))
    }

    const fn kind(&self) -> ApprovalScopeKind {
        match self.0 {
            Scope::ExactAction => ApprovalScopeKind::ExactAction,
            Scope::PathSet { .. } => ApprovalScopeKind::PathSet,
            Scope::PathSubtree { .. } => ApprovalScopeKind::PathSubtree,
            Scope::ExecutableAndArgv { .. } => ApprovalScopeKind::ExecutableAndArgv,
            Scope::HostAndMethods { .. } => ApprovalScopeKind::HostAndMethods,
            Scope::CredentialUse { .. } => ApprovalScopeKind::CredentialUse,
        }
    }

    /// Whether the action that asks is within the breadth it asks for --
    /// at grant time, on what this module can see. Membership at spend is
    /// the registry's, on each action's own canonical form.
    fn admits(
        &self,
        verb: Verb,
        resource: &BoundResource,
        arguments: &BoundArguments,
        credentials: &BoundCredentials,
    ) -> bool {
        match (&self.0, &resource.0) {
            (Scope::ExactAction, _) => true,
            (Scope::PathSet { verb: v, files }, Resource::File(identity)) => {
                *v == verb && files.contains(identity)
            }
            (Scope::PathSubtree { verbs, .. }, Resource::File(_) | Resource::Vacant { .. }) => {
                verbs.contains(&verb)
            }
            (Scope::ExecutableAndArgv { executable, .. }, Resource::Executable(identity)) => {
                executable == identity
            }
            (Scope::HostAndMethods { host, methods }, Resource::Host(target)) => {
                host == target
                    && match &arguments.0 {
                        Arguments::Http { method, .. } => methods
                            .methods()
                            .iter()
                            .any(|m| m.as_str() == method.as_str()),
                        _ => false,
                    }
            }
            (Scope::CredentialUse { handle, host, port }, Resource::Host(target)) => {
                credentials.holds(handle) && &target.name == host && target.port == *port
            }
            (Scope::CredentialUse { handle, .. }, Resource::Credential(target)) => {
                handle == target && credentials.holds(handle)
            }
            _ => false,
        }
    }

    fn value(&self) -> Result<Value, BindingError> {
        let kind = self.kind().as_str();
        match &self.0 {
            Scope::ExactAction => tagged(kind, Vec::new()),
            Scope::PathSet { verb, files } => {
                let files: Vec<Value> = files.iter().map(|f| file(*f)).collect::<Result<_, _>>()?;
                tagged(
                    kind,
                    vec![
                        ("verb", text(&verb.to_string())),
                        ("files", set(files, true)?),
                    ],
                )
            }
            Scope::PathSubtree { root, verbs } => {
                let verbs = verbs.iter().map(|v| text(&v.to_string())).collect();
                tagged(
                    kind,
                    vec![("root", file(*root)?), ("verbs", set(verbs, true)?)],
                )
            }
            Scope::ExecutableAndArgv {
                executable: e,
                argv,
            } => {
                let tokens = argv.tokens().iter().map(|t| text(t.as_str())).collect();
                tagged(
                    kind,
                    vec![
                        ("executable", executable(e)?),
                        ("argv_allowlist", set(tokens, true)?),
                    ],
                )
            }
            Scope::HostAndMethods { host, methods } => {
                let mut members = host.members()?;
                let methods = methods.methods().iter().map(|m| text(m.as_str())).collect();
                members.push(("methods", set(methods, true)?));
                tagged(kind, members)
            }
            Scope::CredentialUse {
                handle,
                host,
                port: p,
            } => tagged(
                kind,
                vec![
                    ("handle", text(handle.as_str())),
                    ("host", text(host)),
                    ("port", port(*p)),
                ],
            ),
        }
    }
}

fn bounded(len: usize, required: bool) -> Result<(), BindingError> {
    if len > MAX_SET_MEMBERS {
        return Err(BindingError::TooManyMembers);
    }
    if required && len == 0 {
        return Err(BindingError::EmptySet);
    }
    Ok(())
}

/// An obligation, explicitly: its name as `kind`, and its parameter, if it
/// has one, as a named member. Never a rendering of the type.
fn obligation(obligation: &Obligation) -> Result<Value, BindingError> {
    let parameter = match obligation {
        Obligation::ForceEnvironment(profile) | Obligation::RedactProfile(profile) => {
            vec![("profile", text(profile.as_str()))]
        }
        Obligation::MaxOutputBytes(bytes) => vec![("bytes", unsigned(*bytes))],
        Obligation::AuditLevel(level) => vec![("level", text(level.as_str()))],
        Obligation::RequireArtifactCapture
        | Obligation::NetworkDeny
        | Obligation::ReadOnlyWorkspace
        | Obligation::SingleUseOnly
        | Obligation::ForceQuarantinedRead
        | Obligation::WorkspaceExecHygiene => Vec::new(),
    };
    tagged(obligation.name(), parameter)
}

/// The decided capability's privacy constraint, or `null` where it carries
/// none. Only `model.call` carries one, and it has no canonical resource
/// identity yet ([`fits`] refuses it): for every verb a binding is built for
/// today the member is `null`, and it is bound so that it cannot later be
/// otherwise unnoticed.
fn privacy(class: Option<PrivacyClass>) -> Value {
    class.map_or(Value::Null, |class| text(class.as_str()))
}

fn obligations(obligations: &Obligations) -> Result<Value, BindingError> {
    let members = obligations
        .as_slice()
        .iter()
        .map(obligation)
        .collect::<Result<Vec<_>, _>>()?;
    set(members, false)
}

// ---------------------------------------------------------------------------
// The run.
// ---------------------------------------------------------------------------

/// What a run contributes: who asked, under which agent profile, in which
/// workspace, at what taint. Read from the run's own record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunContext {
    requester: AuthenticatedSubject,
    agent: BoundAgent,
    workspace: BoundWorkspace,
    taint: TaintLevel,
}

impl RunContext {
    /// Assemble a run's context from values its record holds.
    pub(in crate::state) const fn new(
        requester: AuthenticatedSubject,
        agent: BoundAgent,
        workspace: BoundWorkspace,
        taint: TaintLevel,
    ) -> Self {
        Self {
            requester,
            agent,
            workspace,
            taint,
        }
    }

    /// The run's context, from its record: the subject the kernel reported
    /// when it was admitted, its agent profile and revision, its session's
    /// workspace and that workspace's recorded root, and its taint now.
    ///
    /// `Ok(Err(..))` for a run that is unknown or no longer active.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] for a store that cannot be read, or that holds a
    /// value it could not have written.
    pub(in crate::state) fn load(
        work: &Work<'_>,
        run: &RunId,
    ) -> Result<Result<Self, BindingError>, AuthorityError> {
        let malformed = AuthorityError::Invariant;
        // `run` ⋈ `session_workspace` ⋈ `workspace_root`: one row, or none.
        let row = work.db(work
            .tx
            .query_row(
                "SELECT r.subject, r.agent_profile, r.agent_profile_revision, r.state, \
                     w.workspace_id, root.root_device, root.root_inode, root.birth_sec, \
                     root.birth_nsec FROM run r \
                     JOIN session_workspace w ON w.session_id = r.session_id \
                     JOIN workspace_root root ON root.workspace_id = w.workspace_id \
                     WHERE r.run_id = ?1",
                [run.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                    ))
                },
            )
            .optional())?;
        let Some((subject, profile, revision, state, workspace, device, inode, sec, nsec)) = row
        else {
            return Ok(Err(BindingError::RunUnavailable));
        };
        if state != "ACTIVE" {
            return Ok(Err(BindingError::RunUnavailable));
        }
        let requester =
            stored_subject(&subject).ok_or(malformed("a stored run subject is malformed"))?;
        let agent = BoundAgent::recorded(&profile, revision)
            .map_err(|_| malformed("a stored run profile is malformed"))?;
        let id =
            WorkspaceId::new(&workspace).ok_or(malformed("a stored workspace id is malformed"))?;
        let birth = match (sec, nsec) {
            (Some(seconds), Some(nanoseconds)) => Some(crate::resource::fs::BirthTime {
                seconds,
                nanoseconds: u32::try_from(nanoseconds)
                    .map_err(|_| malformed("a stored root birth time is malformed"))?,
            }),
            (None, None) => None,
            _ => return Err(malformed("a stored root birth time is malformed")),
        };
        let root = RootFingerprint::new(
            device
                .parse()
                .map_err(|_| malformed("a stored root device is malformed"))?,
            inode
                .parse()
                .map_err(|_| malformed("a stored root inode is malformed"))?,
            birth,
        );
        let taint = taint::run_taint(work, run.as_str())?;
        Ok(Ok(Self::new(
            requester,
            agent,
            BoundWorkspace::recorded(id, root),
            taint,
        )))
    }
}

/// A subject as the store spells it: `uid:` and the decimal uid, exactly as
/// [`AuthenticatedSubject::storage_key`] wrote it -- no sign, no leading
/// zero, nothing after.
fn stored_subject(stored: &str) -> Option<AuthenticatedSubject> {
    let digits = stored.strip_prefix("uid:")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let subject = AuthenticatedSubject::unix_uid(digits.parse().ok()?);
    (subject.storage_key() == stored).then_some(subject)
}

// ---------------------------------------------------------------------------
// The binding.
// ---------------------------------------------------------------------------

/// Everything one binding is built from. Every field is required: there is
/// no default for any of them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BindingInput<'a> {
    /// The canonical action policy decided on.
    pub(crate) action: &'a CanonicalAction,
    /// Policy's decision on it: a `REQUIRE_APPROVAL`, or no binding.
    pub(crate) decision: &'a Decision,
    /// Whether the route keeps every obligation the decision carries -- the
    /// route's own answer, as it gives it for an `ALLOW`.
    pub(crate) obligations_kept: bool,
    /// The run.
    pub(crate) run: &'a RunContext,
    /// Where the action would run.
    pub(crate) environment: &'a BoundEnvironment,
    /// What it is on.
    pub(crate) resource: &'a BoundResource,
    /// What it does.
    pub(crate) arguments: &'a BoundArguments,
    /// With which credentials.
    pub(crate) credentials: &'a BoundCredentials,
    /// How broad an approval it would be.
    pub(crate) scope: &'a BoundScope,
}

/// A canonical approval binding and its hash. Holding one grants nothing.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ApprovalBinding {
    canonical: Vec<u8>,
    hash: Sha256Hash,
}

impl fmt::Debug for ApprovalBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApprovalBinding({})", self.hash)
    }
}

impl ApprovalBinding {
    /// Build a binding, or say why there is none.
    ///
    /// # Errors
    ///
    /// A [`BindingError`] for every way the inputs fail to describe one
    /// approvable action completely and consistently.
    pub(in crate::state) fn new(input: &BindingInput<'_>) -> Result<Self, BindingError> {
        let BindingInput {
            action,
            decision,
            obligations_kept,
            run,
            environment,
            resource,
            arguments,
            credentials,
            scope,
        } = *input;
        if decision.effect() != Effect::RequireApproval {
            return Err(BindingError::NotApprovable);
        }
        let spec = decision.approval().ok_or(BindingError::NotApprovable)?;
        if action.capability() != decision.required_capability() {
            return Err(BindingError::ActionMismatch);
        }
        if environment.environment() != *action.environment() {
            return Err(BindingError::EnvironmentMismatch);
        }
        let verb = decision.required_capability().verb();
        fits(verb, resource, arguments)?;
        if scope.kind() != spec.scope() {
            return Err(BindingError::ScopeMismatch);
        }
        if !scope.admits(verb, resource, arguments, credentials) {
            return Err(BindingError::ScopeMismatch);
        }
        if !obligations_kept {
            return Err(BindingError::ObligationUnenforceable);
        }
        let privacy = privacy(decision.required_capability().constraints().privacy_class);
        let value = object(vec![
            ("schema", text(SCHEMA)),
            ("verb", text(&verb.to_string())),
            ("resource_identity", resource.value()?),
            ("canonical_args", arguments.value()?),
            ("workspace", run.workspace.value()?),
            ("environment_profile", environment.value()?),
            ("credential_handles", credentials.value()?),
            ("agent", run.agent.value()?),
            ("requester", text(&run.requester.storage_key())),
            ("scope", scope.value()?),
            ("taint_level", text(run.taint.as_str())),
            ("privacy_class", privacy),
            ("obligations", obligations(decision.obligations())?),
        ])?;
        let canonical = json::to_canonical_bytes(&value);
        if canonical.len() > MAX_CANONICAL_BYTES {
            return Err(BindingError::TooLarge);
        }
        let hash = digest::plain(&canonical);
        Ok(Self { canonical, hash })
    }

    /// The canonical bytes: RFC 8785, UTF-8.
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// `SHA256` of [`Self::canonical_bytes`].
    pub(crate) const fn binding_hash(&self) -> Sha256Hash {
        self.hash
    }
}

/// Whether a resource and arguments fit a verb. The four namespaces the
/// authority performs, and only those: a verb with no canonical identity
/// producer has no binding.
fn fits(
    verb: Verb,
    resource: &BoundResource,
    arguments: &BoundArguments,
) -> Result<(), BindingError> {
    let action = verb.action();
    let resource_fits = match (verb.namespace(), &resource.0) {
        (Namespace::Fs, Resource::Vacant { .. }) => {
            matches!(action, Action::Write | Action::Create)
        }
        (Namespace::Fs, Resource::File(_))
        | (Namespace::Process, Resource::Executable(_))
        | (Namespace::Network, Resource::Host(_))
        | (Namespace::Secret, Resource::Credential(_)) => true,
        _ => false,
    };
    if !resource_fits {
        return Err(BindingError::ResourceMismatch);
    }
    let arguments_fit = match (verb.namespace(), &arguments.0) {
        // A write binds its content; a create may (a write's) or may not (a
        // move's); nothing else moves content into the workspace.
        (Namespace::Fs, Arguments::FsContent { .. }) => {
            matches!(action, Action::Write | Action::Create)
        }
        (Namespace::Fs, Arguments::Fs { .. }) => action != Action::Write,
        (Namespace::Process, Arguments::Argv(_))
        | (Namespace::Network, Arguments::Http { .. })
        | (Namespace::Secret, Arguments::None) => true,
        _ => false,
    };
    if arguments_fit {
        Ok(())
    } else {
        Err(BindingError::ArgumentsMismatch)
    }
}

#[cfg(test)]
#[path = "binding_tests.rs"]
mod tests;

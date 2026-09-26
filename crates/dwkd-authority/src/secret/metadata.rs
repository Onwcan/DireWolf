//! The operator's secret metadata (ADR-0046 §§2, 3): what a handle means, where
//! its value lives and how it may be injected. **Metadata only**: the file has
//! no member that could hold a value, and the parser refuses any member it
//! does not know.
//!
//! ```toml
//! schema_version = 1
//!
//! [age]                                  # how age files are decrypted
//! identity_keychain = "direwolf-age-id"  # a keychain entry: never a file, never a TOML value
//! identity_kind     = "x25519"           # x25519 | scrypt
//!
//! [secrets.github-primary]
//! type         = "bearer"
//! description  = "GitHub API, repo scope"
//! storage      = "keychain"              # keychain | age   (env, exec: refused, ADR-0046 §7)
//! keychain     = "direwolf/github-primary"
//! origins      = ["api.github.com", "uploads.github.com"]
//! header       = "Authorization"
//! prefix       = "Bearer "
//! injection    = ["egress"]              # egress | env_at_spawn | fd_at_spawn
//! rotate_after = "90d"
//! sensitivity  = "high"
//!
//! [secrets.deploy-key]
//! type      = "ssh_private_key"
//! storage   = "age"
//! path      = "/etc/direwolf/secrets/deploy-key.age"
//! injection = ["fd_at_spawn"]
//! consumers = ["/usr/bin/ssh", "/usr/bin/git"]
//! ```
//!
//! `plaintext_to_model` (mode D) is refused: it needs M6's per-use approval
//! and is unreachable until then. The runtime chooses none of this: not the
//! header, not the prefix, not the environment variable, not the mode.

use core::fmt;
use std::collections::BTreeSet;

use toml::de::{DeTable, DeValue};

use crate::capability::{Endpoint, Label};

/// The only schema version this build reads.
pub const SCHEMA_VERSION: i64 = 1;
/// The most secrets one configuration may hold: the redaction index is
/// bounded by the same number (ADR-0046 §21).
pub const MAX_SECRETS: usize = 64;
/// The largest metadata file read.
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
/// The most origins, consumers or modes one secret may name.
pub const MAX_LIST: usize = 16;
/// The longest free-text member (a description).
pub const MAX_TEXT_CHARS: usize = 256;

/// A secret's handle: `[a-z][a-z0-9._-]{0,63}`. Non-secret by design: it may
/// appear in prompts, logs and audit records without consequence. Stricter
/// than the capability grammar's [`Label`], so every handle is also a valid
/// `secret.use:<handle>` scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretHandle(String);

impl SecretHandle {
    /// The longest handle.
    pub const MAX_CHARS: usize = 64;

    /// A handle, or `None` for text outside the grammar.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        let mut chars = text.chars();
        let first = chars.next()?;
        let ok = first.is_ascii_lowercase()
            && text.len() <= Self::MAX_CHARS
            && chars.all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
            });
        (ok && Label::new(text).is_some()).then(|| Self(text.to_owned()))
    }

    /// The handle.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What kind of credential a secret is. Informational for policy and audit;
/// the value is never inspected against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretType {
    /// A bearer token.
    Bearer,
    /// An API key.
    ApiKey,
    /// A password.
    Password,
    /// An SSH private key.
    SshPrivateKey,
    /// A TLS private key, possibly with its certificate chain.
    TlsPrivateKey,
    /// A connection string with an embedded credential.
    ConnectionString,
    /// Anything else.
    Generic,
}

impl SecretType {
    /// Every type.
    pub const ALL: [Self; 7] = [
        Self::Bearer,
        Self::ApiKey,
        Self::Password,
        Self::SshPrivateKey,
        Self::TlsPrivateKey,
        Self::ConnectionString,
        Self::Generic,
    ];

    /// The spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::ApiKey => "api_key",
            Self::Password => "password",
            Self::SshPrivateKey => "ssh_private_key",
            Self::TlsPrivateKey => "tls_private_key",
            Self::ConnectionString => "connection_string",
            Self::Generic => "generic",
        }
    }
}

/// Where a secret's value lives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Storage {
    /// The OS keychain: the Linux kernel keyring, the macOS Keychain, the
    /// Windows Credential Manager. The entry name.
    Keychain(KeychainEntry),
    /// An age-encrypted file at an operator-chosen absolute path, decrypted
    /// with the configuration's `[age]` identity.
    Age(AgeFile),
}

impl Storage {
    /// The backend's name.
    #[must_use]
    pub const fn backend(&self) -> &'static str {
        match self {
            Self::Keychain(_) => "keychain",
            Self::Age(_) => "age",
        }
    }

    /// The non-secret reference: the entry name or the file path.
    #[must_use]
    pub fn reference(&self) -> &str {
        match self {
            Self::Keychain(entry) => entry.as_str(),
            Self::Age(file) => file.as_str(),
        }
    }
}

/// A keychain entry name: `[a-z0-9][a-z0-9._:/@-]{0,127}`. On Linux it is the
/// description of a `user` key in the authority's user keyring; on macOS and
/// Windows the account under the service `direwolf`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeychainEntry(String);

impl KeychainEntry {
    /// The longest name.
    pub const MAX_CHARS: usize = 128;

    /// An entry name, or `None`.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        let mut chars = text.chars();
        let first = chars.next()?;
        let ok = (first.is_ascii_lowercase() || first.is_ascii_digit())
            && text.len() <= Self::MAX_CHARS
            && chars.all(|c| {
                c.is_ascii_lowercase()
                    || c.is_ascii_digit()
                    || matches!(c, '.' | '_' | ':' | '/' | '@' | '-')
            });
        ok.then(|| Self(text.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An age file's absolute path: `/`-separated components of
/// `[A-Za-z0-9._-]`, no `.`/`..`/empty component, at most 1024 bytes. The
/// runtime never chooses it; the backend checks the file itself (ADR-0046 §8).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgeFile(String);

impl AgeFile {
    /// The longest path.
    pub const MAX_BYTES: usize = 1024;

    /// A path, or `None`.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        let rest = text.strip_prefix('/')?;
        let ok = text.len() <= Self::MAX_BYTES
            && !rest.is_empty()
            && rest.split('/').all(|component| {
                !component.is_empty()
                    && component != "."
                    && component != ".."
                    && component
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            });
        ok.then(|| Self(text.to_owned()))
    }

    /// The path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path's components.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|c| !c.is_empty())
    }
}

/// How the value reaches its consumer (SECRETS.md §3), most restrictive first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InjectionMode {
    /// (A) The broker adds a header to an egress request; the consumer never
    /// holds the value.
    Egress,
    /// (C) A one-shot descriptor at spawn: not in the environment, not in argv.
    FdAtSpawn,
    /// (B) An environment variable at spawn.
    EnvAtSpawn,
}

impl InjectionMode {
    /// The spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Egress => "egress",
            Self::FdAtSpawn => "fd_at_spawn",
            Self::EnvAtSpawn => "env_at_spawn",
        }
    }
}

/// How sensitive a secret is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sensitivity {
    /// The default.
    Normal,
    /// High.
    High,
    /// Critical.
    Critical,
}

impl Sensitivity {
    /// The spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// An HTTP header name, as RFC 9110 §5.1 defines a token. Operator-chosen.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HeaderName(String);

impl HeaderName {
    /// A header name, or `None`.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        let ok = !text.is_empty()
            && text.len() <= 64
            && text.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            });
        ok.then(|| Self(text.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A header value prefix (`"Bearer "`): printable ASCII and space, no CR, LF
/// or NUL — refused, never sanitised. Operator-chosen.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HeaderPrefix(String);

impl HeaderPrefix {
    /// A prefix, or `None`.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        let ok = text.len() <= 64 && text.bytes().all(|b| b == b' ' || b.is_ascii_graphic());
        ok.then(|| Self(text.to_owned()))
    }

    /// The prefix.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An environment variable a secret may be injected as (mode B):
/// `[A-Z_][A-Z0-9_]{0,63}`, and never one that controls how a process runs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvName(String);

/// Variables that change how a process (or its loader, its interpreter, its
/// shell, git) behaves: a secret injected as one would be an execution-control
/// primitive, not a credential. Prefix families end in `*`.
const CONTROL_VARIABLES: &[&str] = &[
    "LD_*",
    "DYLD_*",
    "PATH",
    "HOME",
    "LANG",
    "LC_*",
    "SHELL",
    "ENV",
    "BASH_ENV",
    "BASH_FUNC_*",
    "SHELLOPTS",
    "BASHOPTS",
    "IFS",
    "PS4",
    "PROMPT_COMMAND",
    "PYTHON*",
    "PERL5*",
    "PERLLIB",
    "RUBY*",
    "GEM_*",
    "NODE_*",
    "NPM_CONFIG_*",
    "RUSTC*",
    "RUSTFLAGS",
    "RUSTDOC*",
    "CARGO_*",
    "GIT_*",
    "SSH_ASKPASS",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "TMPDIR",
    "MALLOC_*",
    "GLIBC_TUNABLES",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "CLASSPATH",
    "GCONV_PATH",
    "NLSPATH",
    "LOCPATH",
    "HOSTALIASES",
    "RES_OPTIONS",
    "LOCALDOMAIN",
    "OPENSSL_*",
    "SSL_CERT_*",
];

impl EnvName {
    /// A name, or `None` for a malformed or control variable.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        let mut chars = text.chars();
        let first = chars.next()?;
        let ok = (first.is_ascii_uppercase() || first == '_')
            && text.len() <= 64
            && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        let control = CONTROL_VARIABLES
            .iter()
            .any(|pattern| match pattern.strip_suffix('*') {
                Some(family) => text.starts_with(family),
                None => text == *pattern,
            });
        (ok && !control).then(|| Self(text.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One configured secret: every member but the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMetadata {
    /// The handle.
    pub handle: SecretHandle,
    /// The kind of credential.
    pub secret_type: SecretType,
    /// Free text for the operator.
    pub description: String,
    /// Where the value lives.
    pub storage: Storage,
    /// Origins an egress injection may reach (mode A), in the capability
    /// layer's endpoint grammar.
    pub origins: Vec<Endpoint>,
    /// The header an egress injection sets (mode A).
    pub header: Option<HeaderName>,
    /// What precedes the value in that header.
    pub prefix: Option<HeaderPrefix>,
    /// The modes this secret may be injected by: an allowlist, never a request.
    pub injection: BTreeSet<InjectionMode>,
    /// Executables that may receive the value at spawn (modes B, C), as the
    /// operator spelled them; the state layer resolves each to an executable
    /// identity when the metadata is loaded.
    pub consumers: Vec<String>,
    /// The environment variable a mode-B injection sets.
    pub env: Option<EnvName>,
    /// Days after which `direwolf doctor` should warn.
    pub rotate_after_days: Option<u32>,
    /// Sensitivity.
    pub sensitivity: Sensitivity,
    /// Revoked: every resolution fails closed.
    pub revoked: bool,
}

/// The `[age]` section: which keychain entry holds the age identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgeIdentitySource {
    /// The keychain entry.
    pub keychain: KeychainEntry,
    /// What that entry holds.
    pub kind: AgeIdentityKind,
}

/// What an age identity entry holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgeIdentityKind {
    /// An X25519 secret key, `AGE-SECRET-KEY-1…`.
    X25519,
    /// A passphrase, for files encrypted to an scrypt recipient.
    Scrypt,
}

/// A whole metadata document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecretConfig {
    /// Every secret, ordered by handle.
    pub secrets: Vec<SecretMetadata>,
    /// The age identity, when any secret is stored with age.
    pub age: Option<AgeIdentitySource>,
}

impl SecretConfig {
    /// The secret with `handle`.
    #[must_use]
    pub fn get(&self, handle: &SecretHandle) -> Option<&SecretMetadata> {
        self.secrets.iter().find(|s| &s.handle == handle)
    }
}

/// Why a metadata document was refused. Carries the member's path and line —
/// never a value, because the document holds none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// The 1-based line, when the parser reported one.
    pub line: Option<u32>,
    /// The member, as `secrets.<handle>.<field>`.
    pub field: String,
    /// What was wrong.
    pub kind: ConfigErrorKind,
}

/// The category of a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigErrorKind {
    /// The document is larger than [`MAX_CONFIG_BYTES`].
    TooLarge,
    /// Not TOML.
    Syntax,
    /// `schema_version` is missing or not [`SCHEMA_VERSION`].
    SchemaVersion,
    /// A member this schema does not have.
    UnknownField,
    /// A required member is absent.
    MissingField,
    /// A member of the wrong type.
    TypeMismatch,
    /// A value outside its grammar.
    BadValue,
    /// More secrets than [`MAX_SECRETS`], or a list longer than [`MAX_LIST`].
    TooMany,
    /// `storage = "env"` or `"exec"`: deferred (ADR-0046 §7).
    BackendDeferred,
    /// `plaintext_to_model`: unreachable until M6 (ADR-0046 §14).
    ModeUnreachable,
    /// A mode was allowed without what it needs (origins and a header for
    /// egress, consumers for spawn, an environment name for env).
    Incomplete,
    /// A secret is stored with age but there is no `[age]` identity.
    NoAgeIdentity,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            ConfigErrorKind::TooLarge => "the document is too large",
            ConfigErrorKind::Syntax => "not a TOML document",
            ConfigErrorKind::SchemaVersion => "schema_version must be 1",
            ConfigErrorKind::UnknownField => "unknown member",
            ConfigErrorKind::MissingField => "missing member",
            ConfigErrorKind::TypeMismatch => "wrong type",
            ConfigErrorKind::BadValue => "value outside its grammar",
            ConfigErrorKind::TooMany => "too many entries",
            ConfigErrorKind::BackendDeferred => {
                "storage env and exec are not implemented (ADR-0046 section 7)"
            }
            ConfigErrorKind::ModeUnreachable => {
                "plaintext_to_model is unreachable until approvals exist (M6)"
            }
            ConfigErrorKind::Incomplete => "an allowed injection mode lacks what it needs",
            ConfigErrorKind::NoAgeIdentity => "an age secret needs an [age] identity",
        };
        match self.line {
            Some(line) => write!(f, "line {line}: {}: {kind}", self.field),
            None => write!(f, "{}: {kind}", self.field),
        }
    }
}

impl std::error::Error for ConfigError {}

const TOP_LEVEL: &[&str] = &["schema_version", "age", "secrets"];
const AGE: &[&str] = &["identity_keychain", "identity_kind"];
const SECRET: &[&str] = &[
    "type",
    "description",
    "storage",
    "keychain",
    "path",
    "origins",
    "header",
    "prefix",
    "injection",
    "consumers",
    "env",
    "rotate_after",
    "sensitivity",
    "revoked",
];

type Value<'t> = toml::Spanned<DeValue<'t>>;

struct Walker<'a> {
    text: &'a str,
}

impl Walker<'_> {
    fn line(&self, span: &core::ops::Range<usize>) -> Option<u32> {
        let counted = self
            .text
            .get(..span.start)?
            .bytes()
            .filter(|b| *b == b'\n')
            .count();
        u32::try_from(counted).ok().map(|n| n.saturating_add(1))
    }

    fn error(&self, value: Option<&Value<'_>>, field: &str, kind: ConfigErrorKind) -> ConfigError {
        ConfigError {
            line: value.and_then(|v| self.line(&v.span())),
            field: field.to_owned(),
            kind,
        }
    }

    /// The error for member `name` of the table at `path`: located at the
    /// member, or at the table when the member is absent.
    fn member_error(
        &self,
        table: &DeTable<'_>,
        value: &Value<'_>,
        path: &str,
        name: &str,
        kind: ConfigErrorKind,
    ) -> ConfigError {
        self.error(
            find(table, name).or(Some(value)),
            &format!("{path}{name}"),
            kind,
        )
    }

    fn reject_unknown(
        &self,
        table: &DeTable<'_>,
        allowed: &[&str],
        path: &str,
    ) -> Result<(), ConfigError> {
        for (key, _) in table {
            let name: &str = key.get_ref().as_ref();
            if !allowed.contains(&name) {
                return Err(ConfigError {
                    line: self.line(&key.span()),
                    field: format!("{path}{name}"),
                    kind: ConfigErrorKind::UnknownField,
                });
            }
        }
        Ok(())
    }

    fn string<'t>(
        &self,
        table: &'t DeTable<'t>,
        name: &str,
        path: &str,
    ) -> Result<Option<&'t str>, ConfigError> {
        let Some(value) = find(table, name) else {
            return Ok(None);
        };
        let field = format!("{path}{name}");
        let DeValue::String(text) = value.get_ref() else {
            return Err(self.error(Some(value), &field, ConfigErrorKind::TypeMismatch));
        };
        let text: &str = text.as_ref();
        if text.chars().count() > MAX_TEXT_CHARS {
            return Err(self.error(Some(value), &field, ConfigErrorKind::BadValue));
        }
        Ok(Some(text))
    }

    fn strings<'t>(
        &self,
        table: &'t DeTable<'t>,
        name: &str,
        path: &str,
    ) -> Result<Vec<&'t str>, ConfigError> {
        let Some(value) = find(table, name) else {
            return Ok(Vec::new());
        };
        let field = format!("{path}{name}");
        let DeValue::Array(array) = value.get_ref() else {
            return Err(self.error(Some(value), &field, ConfigErrorKind::TypeMismatch));
        };
        if array.len() > MAX_LIST {
            return Err(self.error(Some(value), &field, ConfigErrorKind::TooMany));
        }
        let mut out = Vec::new();
        for item in array {
            let DeValue::String(text) = item.get_ref() else {
                return Err(self.error(Some(item), &field, ConfigErrorKind::TypeMismatch));
            };
            let text: &str = text.as_ref();
            if text.chars().count() > MAX_TEXT_CHARS {
                return Err(self.error(Some(item), &field, ConfigErrorKind::BadValue));
            }
            out.push(text);
        }
        Ok(out)
    }

    fn secret(
        &self,
        handle: SecretHandle,
        table: &DeTable<'_>,
        value: &Value<'_>,
    ) -> Result<SecretMetadata, ConfigError> {
        let path = format!("secrets.{handle}.");
        self.reject_unknown(table, SECRET, &path)?;
        let at = |name: &str| find(table, name);
        let bad = |name: &str, kind| self.member_error(table, value, &path, name, kind);

        let secret_type = match self.string(table, "type", &path)? {
            Some(text) => SecretType::ALL
                .into_iter()
                .find(|t| t.as_str() == text)
                .ok_or_else(|| bad("type", ConfigErrorKind::BadValue))?,
            None => return Err(bad("type", ConfigErrorKind::MissingField)),
        };
        let description = self
            .string(table, "description", &path)?
            .unwrap_or_default()
            .to_owned();

        let storage = self.storage(table, value, &path)?;

        let mut origins = Vec::new();
        for text in self.strings(table, "origins", &path)? {
            let origin =
                Endpoint::parse(text).map_err(|_| bad("origins", ConfigErrorKind::BadValue))?;
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
        let header = match self.string(table, "header", &path)? {
            Some(text) => Some(
                HeaderName::new(text).ok_or_else(|| bad("header", ConfigErrorKind::BadValue))?,
            ),
            None => None,
        };
        let prefix = match self.string(table, "prefix", &path)? {
            Some(text) => Some(
                HeaderPrefix::new(text).ok_or_else(|| bad("prefix", ConfigErrorKind::BadValue))?,
            ),
            None => None,
        };
        let injection = self.injection(table, value, &path)?;
        let consumers = self.consumers(table, value, &path)?;
        let env = match self.string(table, "env", &path)? {
            Some(text) => {
                Some(EnvName::new(text).ok_or_else(|| bad("env", ConfigErrorKind::BadValue))?)
            }
            None => None,
        };
        let rotate_after_days = self.rotate_after(table, value, &path)?;
        let sensitivity = match self.string(table, "sensitivity", &path)? {
            None | Some("normal") => Sensitivity::Normal,
            Some("high") => Sensitivity::High,
            Some("critical") => Sensitivity::Critical,
            Some(_) => return Err(bad("sensitivity", ConfigErrorKind::BadValue)),
        };
        let revoked = match at("revoked") {
            None => false,
            Some(value) => match value.get_ref() {
                DeValue::Boolean(flag) => *flag,
                _ => return Err(bad("revoked", ConfigErrorKind::TypeMismatch)),
            },
        };

        // A mode is allowed only with what it needs.
        if injection.contains(&InjectionMode::Egress) && (origins.is_empty() || header.is_none()) {
            return Err(bad("injection", ConfigErrorKind::Incomplete));
        }
        let spawns = injection.contains(&InjectionMode::EnvAtSpawn)
            || injection.contains(&InjectionMode::FdAtSpawn);
        if spawns && consumers.is_empty() {
            return Err(bad("consumers", ConfigErrorKind::Incomplete));
        }
        if injection.contains(&InjectionMode::EnvAtSpawn) != env.is_some() {
            return Err(bad("env", ConfigErrorKind::Incomplete));
        }
        if !injection.contains(&InjectionMode::Egress)
            && (header.is_some() || prefix.is_some() || !origins.is_empty())
        {
            return Err(bad("header", ConfigErrorKind::Incomplete));
        }

        Ok(SecretMetadata {
            handle,
            secret_type,
            description,
            storage,
            origins,
            header,
            prefix,
            injection,
            consumers,
            env,
            rotate_after_days,
            sensitivity,
            revoked,
        })
    }

    /// Where a secret's value lives: a keychain entry or an age file, each
    /// with only its own member. `env` and `exec` are deferred.
    fn storage(
        &self,
        table: &DeTable<'_>,
        value: &Value<'_>,
        path: &str,
    ) -> Result<Storage, ConfigError> {
        let bad = |name: &str, kind| self.member_error(table, value, path, name, kind);
        match self.string(table, "storage", path)? {
            Some("keychain") => {
                if find(table, "path").is_some() {
                    return Err(bad("path", ConfigErrorKind::UnknownField));
                }
                let entry = self
                    .string(table, "keychain", path)?
                    .ok_or_else(|| bad("keychain", ConfigErrorKind::MissingField))?;
                Ok(Storage::Keychain(KeychainEntry::new(entry).ok_or_else(
                    || bad("keychain", ConfigErrorKind::BadValue),
                )?))
            }
            Some("age") => {
                if find(table, "keychain").is_some() {
                    return Err(bad("keychain", ConfigErrorKind::UnknownField));
                }
                let file = self
                    .string(table, "path", path)?
                    .ok_or_else(|| bad("path", ConfigErrorKind::MissingField))?;
                Ok(Storage::Age(
                    AgeFile::new(file).ok_or_else(|| bad("path", ConfigErrorKind::BadValue))?,
                ))
            }
            Some("env" | "exec") => Err(bad("storage", ConfigErrorKind::BackendDeferred)),
            Some(_) => Err(bad("storage", ConfigErrorKind::BadValue)),
            None => Err(bad("storage", ConfigErrorKind::MissingField)),
        }
    }

    /// The modes a secret may be injected by: at least one; mode D refused.
    fn injection(
        &self,
        table: &DeTable<'_>,
        value: &Value<'_>,
        path: &str,
    ) -> Result<BTreeSet<InjectionMode>, ConfigError> {
        let bad = |kind| self.member_error(table, value, path, "injection", kind);
        let mut injection = BTreeSet::new();
        for text in self.strings(table, "injection", path)? {
            let mode = match text {
                "egress" => InjectionMode::Egress,
                "fd_at_spawn" => InjectionMode::FdAtSpawn,
                "env_at_spawn" => InjectionMode::EnvAtSpawn,
                "plaintext_to_model" => return Err(bad(ConfigErrorKind::ModeUnreachable)),
                _ => return Err(bad(ConfigErrorKind::BadValue)),
            };
            injection.insert(mode);
        }
        if injection.is_empty() {
            return Err(bad(ConfigErrorKind::MissingField));
        }
        Ok(injection)
    }

    /// The consumers a spawn may inject into: absolute, normal paths, once
    /// each. Resolved and hashed when the configuration is loaded.
    fn consumers(
        &self,
        table: &DeTable<'_>,
        value: &Value<'_>,
        path: &str,
    ) -> Result<Vec<String>, ConfigError> {
        let mut consumers = Vec::new();
        for text in self.strings(table, "consumers", path)? {
            if !text.starts_with('/')
                || text.contains("//")
                || text.split('/').any(|c| c == "." || c == "..")
            {
                return Err(self.member_error(
                    table,
                    value,
                    path,
                    "consumers",
                    ConfigErrorKind::BadValue,
                ));
            }
            if !consumers.iter().any(|c: &String| c == text) {
                consumers.push(text.to_owned());
            }
        }
        Ok(consumers)
    }

    /// `rotate_after`: `<days>d`, 1 to 3650, no leading zero.
    fn rotate_after(
        &self,
        table: &DeTable<'_>,
        value: &Value<'_>,
        path: &str,
    ) -> Result<Option<u32>, ConfigError> {
        let Some(text) = self.string(table, "rotate_after", path)? else {
            return Ok(None);
        };
        text.strip_suffix('d')
            .filter(|n| {
                !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && !n.starts_with('0')
            })
            .and_then(|n| n.parse::<u32>().ok())
            .filter(|n| *n <= 3650)
            .map(Some)
            .ok_or_else(|| {
                self.member_error(
                    table,
                    value,
                    path,
                    "rotate_after",
                    ConfigErrorKind::BadValue,
                )
            })
    }
}

fn find<'t>(table: &'t DeTable<'t>, name: &str) -> Option<&'t Value<'t>> {
    table
        .iter()
        .find(|(key, _)| AsRef::<str>::as_ref(key.get_ref()) == name)
        .map(|(_, value)| value)
}

/// Parse a metadata document.
///
/// # Errors
///
/// [`ConfigError`]: the first member that is unknown, missing, mistyped or
/// outside its grammar. A document is accepted whole or not at all.
pub fn parse(text: &str) -> Result<SecretConfig, ConfigError> {
    if text.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError {
            line: None,
            field: String::new(),
            kind: ConfigErrorKind::TooLarge,
        });
    }
    let walker = Walker { text };
    let document = DeTable::parse(text).map_err(|error| ConfigError {
        line: error.span().and_then(|span| walker.line(&span)),
        field: String::new(),
        kind: ConfigErrorKind::Syntax,
    })?;
    let document = document.get_ref();
    walker.reject_unknown(document, TOP_LEVEL, "")?;

    match find(document, "schema_version") {
        Some(value) if matches!(value.get_ref(), DeValue::Integer(i) if i.as_str() == "1") => {}
        value => return Err(walker.error(value, "schema_version", ConfigErrorKind::SchemaVersion)),
    }

    let age = match find(document, "age") {
        None => None,
        Some(value) => {
            let DeValue::Table(table) = value.get_ref() else {
                return Err(walker.error(Some(value), "age", ConfigErrorKind::TypeMismatch));
            };
            walker.reject_unknown(table, AGE, "age.")?;
            let entry = walker
                .string(table, "identity_keychain", "age.")?
                .ok_or_else(|| {
                    walker.error(
                        Some(value),
                        "age.identity_keychain",
                        ConfigErrorKind::MissingField,
                    )
                })?;
            let keychain = KeychainEntry::new(entry).ok_or_else(|| {
                walker.error(
                    find(table, "identity_keychain"),
                    "age.identity_keychain",
                    ConfigErrorKind::BadValue,
                )
            })?;
            let kind = match walker.string(table, "identity_kind", "age.")? {
                None | Some("x25519") => AgeIdentityKind::X25519,
                Some("scrypt") => AgeIdentityKind::Scrypt,
                Some(_) => {
                    return Err(walker.error(
                        find(table, "identity_kind"),
                        "age.identity_kind",
                        ConfigErrorKind::BadValue,
                    ));
                }
            };
            Some(AgeIdentitySource { keychain, kind })
        }
    };

    let mut secrets = Vec::new();
    if let Some(value) = find(document, "secrets") {
        let DeValue::Table(table) = value.get_ref() else {
            return Err(walker.error(Some(value), "secrets", ConfigErrorKind::TypeMismatch));
        };
        if table.len() > MAX_SECRETS {
            return Err(walker.error(Some(value), "secrets", ConfigErrorKind::TooMany));
        }
        for (key, entry) in table {
            let name: &str = key.get_ref().as_ref();
            let handle = SecretHandle::new(name).ok_or_else(|| ConfigError {
                line: walker.line(&key.span()),
                field: "secrets".to_owned(),
                kind: ConfigErrorKind::BadValue,
            })?;
            let DeValue::Table(fields) = entry.get_ref() else {
                return Err(walker.error(
                    Some(entry),
                    &format!("secrets.{handle}"),
                    ConfigErrorKind::TypeMismatch,
                ));
            };
            secrets.push(walker.secret(handle, fields, entry)?);
        }
    }
    secrets.sort_by(|a, b| a.handle.cmp(&b.handle));
    if secrets
        .windows(2)
        .any(|w| matches!(w, [a, b] if a.handle == b.handle))
    {
        return Err(ConfigError {
            line: None,
            field: "secrets".to_owned(),
            kind: ConfigErrorKind::BadValue,
        });
    }
    if age.is_none() && secrets.iter().any(|s| matches!(s.storage, Storage::Age(_))) {
        return Err(ConfigError {
            line: None,
            field: "age".to_owned(),
            kind: ConfigErrorKind::NoAgeIdentity,
        });
    }
    Ok(SecretConfig { secrets, age })
}

#[cfg(test)]
mod tests;

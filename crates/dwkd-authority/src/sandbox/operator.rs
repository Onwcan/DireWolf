//! The operator's sandbox configuration file (M5d.2, ADR-0052 §2a):
//! `dwkd-authority serve --sandbox-config <path>`.
//!
//! It is how a production authority gets an execution environment at all:
//! the runtime client and its socket, the image and the probe by digest, the
//! topology and its egress budgets, the image's manifest and the workload
//! budget — every value [`SandboxConfig`] holds, and nothing else. It is read
//! once, at start, through the same trusted reader as the secret metadata
//! (`crate::secret::backend::read_operator_file`): a regular file owned by
//! root or the authority, writable by nobody else, under directories only
//! they can change. No DWKP operation, flag or variable supplies any of it,
//! and the runtime never sees it.
//!
//! ```toml
//! schema_version = 1
//! runtime = "/usr/bin/docker"
//! socket = "/run/docker.sock"
//! image = "sha256:<64 hex>"
//! probe_sha256 = "<64 hex>"
//! network = "PROXY_ONLY"            # or "NO_NETWORK" (the broker builds it only for evidence)
//!
//! [egress]                          # PROXY_ONLY only, and then required
//! relay_sha256 = "<64 hex>"
//! max_tunnels = 8
//! max_upload_bytes = 1048576
//! max_download_bytes = 67108864
//!
//! [budget]                          # optional: OD-8's defaults
//! workloads = 100
//! seconds = 3600
//!
//! [executables]                     # the image's manifest: path -> SHA-256
//! "/usr/bin/git" = "<64 hex>"
//!
//! [workspace]                       # required (M5d.4, ADR-0052 §§6, 10)
//! quota_bytes = 5368709120          # each workspace's own filesystem: 16 MiB to 16 TiB
//! # unverified_evidence = true      # instead: the evidence harness's scratch directory
//! ```
//!
//! Strict: an unknown member, a missing required one, a value of another
//! type or outside its grammar refuses the whole file, and the authority
//! does not start. There is no field for a runtime flag, a mount, a
//! capability, a device, a user, a group or a weaker profile; the workspace
//! group and its root's mode are the contract's, not the operator's.

use toml::de::{DeTable, DeValue};

use super::{EgressConfig, SandboxConfig, WorkloadBudget, WorkspaceSetting};
use dwk_proto::brokerp::sandbox::{NetworkTopology, WorkspaceQuota};

/// The largest file read.
pub const MAX_FILE_BYTES: u64 = 64 * 1024;

const TOP: &[&str] = &[
    "schema_version",
    "runtime",
    "socket",
    "image",
    "probe_sha256",
    "network",
    "egress",
    "budget",
    "executables",
    "workspace",
];
const EGRESS: &[&str] = &[
    "relay_sha256",
    "max_tunnels",
    "max_upload_bytes",
    "max_download_bytes",
];
const BUDGET: &[&str] = &["workloads", "seconds"];
const WORKSPACE: &[&str] = &["quota_bytes", "unverified_evidence"];

type Value<'t> = toml::Spanned<DeValue<'t>>;

fn find<'t>(table: &'t DeTable<'t>, name: &str) -> Option<&'t Value<'t>> {
    table
        .iter()
        .find(|(key, _)| AsRef::<str>::as_ref(key.get_ref()) == name)
        .map(|(_, value)| value)
}

fn reject_unknown(table: &DeTable<'_>, allowed: &[&str], path: &str) -> Result<(), String> {
    for (key, _) in table {
        let name: &str = key.get_ref().as_ref();
        if !allowed.contains(&name) {
            return Err(format!("unknown member {path}{name}"));
        }
    }
    Ok(())
}

fn string<'t>(table: &'t DeTable<'t>, name: &str, path: &str) -> Result<Option<&'t str>, String> {
    let Some(value) = find(table, name) else {
        return Ok(None);
    };
    match value.get_ref() {
        DeValue::String(text) => Ok(Some(text.as_ref())),
        _ => Err(format!("{path}{name} must be a string")),
    }
}

fn required<'t>(table: &'t DeTable<'t>, name: &str, path: &str) -> Result<&'t str, String> {
    string(table, name, path)?.ok_or_else(|| format!("{path}{name} is required"))
}

/// A non-negative decimal integer, in its one spelling.
fn integer(table: &DeTable<'_>, name: &str, path: &str) -> Result<Option<u64>, String> {
    let Some(value) = find(table, name) else {
        return Ok(None);
    };
    let DeValue::Integer(number) = value.get_ref() else {
        return Err(format!("{path}{name} must be an integer"));
    };
    let text = number.as_str();
    if number.radix() != 10 || text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{path}{name} must be a plain decimal integer"));
    }
    text.parse::<u64>()
        .map(Some)
        .map_err(|_| format!("{path}{name} is out of range"))
}

fn boolean(table: &DeTable<'_>, name: &str, path: &str) -> Result<Option<bool>, String> {
    let Some(value) = find(table, name) else {
        return Ok(None);
    };
    match value.get_ref() {
        DeValue::Boolean(flag) => Ok(Some(*flag)),
        _ => Err(format!("{path}{name} must be true or false")),
    }
}

/// `[workspace]` (M5d.4): every run's workspace -- the operator's bounded
/// filesystem at `quota_bytes`, or, for the evidence harness only,
/// `unverified_evidence = true`. Required: there is no default, and never
/// both.
fn workspace(document: &DeTable<'_>) -> Result<WorkspaceSetting, String> {
    let Some(table) = table(document, "workspace")? else {
        return Err(
            "[workspace] is required: quota_bytes, the bound of each workspace's own filesystem"
                .to_owned(),
        );
    };
    reject_unknown(table, WORKSPACE, "workspace.")?;
    match (
        integer(table, "quota_bytes", "workspace.")?,
        boolean(table, "unverified_evidence", "workspace.")?,
    ) {
        (Some(quota), None) => WorkspaceQuota::new(quota)
            .map(WorkspaceSetting::Bounded)
            .ok_or_else(|| "workspace.quota_bytes must be 16 MiB to 16 TiB".to_owned()),
        (None, Some(true)) => Ok(WorkspaceSetting::UnverifiedEvidence),
        (None, Some(false) | None) => Err("[workspace] needs quota_bytes".to_owned()),
        (Some(_), Some(_)) => {
            Err("[workspace] names quota_bytes or unverified_evidence, never both".to_owned())
        }
    }
}

fn table<'t>(document: &'t DeTable<'t>, name: &str) -> Result<Option<&'t DeTable<'t>>, String> {
    let Some(value) = find(document, name) else {
        return Ok(None);
    };
    match value.get_ref() {
        DeValue::Table(table) => Ok(Some(table)),
        _ => Err(format!("{name} must be a table")),
    }
}

/// Parse one configuration document.
///
/// # Errors
///
/// The first member that is unknown, missing, mistyped or outside its
/// grammar. A document is accepted whole or not at all.
pub fn parse(text: &str) -> Result<SandboxConfig, String> {
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(format!("larger than {MAX_FILE_BYTES} bytes"));
    }
    let document = DeTable::parse(text).map_err(|_| "not a TOML document".to_owned())?;
    let document = document.get_ref();
    reject_unknown(document, TOP, "")?;
    match find(document, "schema_version").map(toml::Spanned::get_ref) {
        Some(DeValue::Integer(version)) if version.radix() == 10 && version.as_str() == "1" => {}
        _ => return Err("schema_version must be 1".to_owned()),
    }
    let runtime = required(document, "runtime", "")?;
    let socket = required(document, "socket", "")?;
    let image = required(document, "image", "")?;
    let probe = required(document, "probe_sha256", "")?;
    let network = match required(document, "network", "")? {
        "PROXY_ONLY" => NetworkTopology::ProxyOnly,
        "NO_NETWORK" => NetworkTopology::NoNetwork,
        _ => return Err("network must be PROXY_ONLY or NO_NETWORK".to_owned()),
    };
    let refused = |error: super::SandboxConfigError| error.to_string();
    let workspace = workspace(document)?;
    let config = match (network, table(document, "egress")?) {
        (NetworkTopology::ProxyOnly, Some(egress)) => {
            reject_unknown(egress, EGRESS, "egress.")?;
            let limit = |name: &str| -> Result<u64, String> {
                integer(egress, name, "egress.")?
                    .ok_or_else(|| format!("egress.{name} is required"))
            };
            let tunnels = u16::try_from(limit("max_tunnels")?)
                .map_err(|_| "egress.max_tunnels is out of range".to_owned())?;
            let egress = EgressConfig::new(
                required(egress, "relay_sha256", "egress.")?,
                tunnels,
                limit("max_upload_bytes")?,
                limit("max_download_bytes")?,
            )
            .map_err(refused)?;
            SandboxConfig::proxy_only(runtime, socket, image, probe, egress, workspace)
                .map_err(refused)?
        }
        (NetworkTopology::ProxyOnly, None) => {
            return Err("a PROXY_ONLY configuration needs its [egress] table".to_owned());
        }
        (NetworkTopology::NoNetwork, None) => {
            SandboxConfig::new(runtime, socket, image, probe, network, workspace)
                .map_err(refused)?
        }
        (NetworkTopology::NoNetwork, Some(_)) => {
            return Err("a NO_NETWORK configuration has no [egress] table".to_owned());
        }
    };
    let mut budget = WorkloadBudget::default();
    if let Some(table) = table(document, "budget")? {
        reject_unknown(table, BUDGET, "budget.")?;
        if let Some(workloads) = integer(table, "workloads", "budget.")? {
            budget.workloads = workloads;
        }
        if let Some(seconds) = integer(table, "seconds", "budget.")? {
            budget.seconds = seconds;
        }
    }
    let mut manifest: Vec<(&str, &str)> = Vec::new();
    if let Some(table) = table(document, "executables")? {
        for (key, value) in table {
            let path: &str = key.get_ref().as_ref();
            let DeValue::String(sha256) = value.get_ref() else {
                return Err(format!("executables.\"{path}\" must be a SHA-256 string"));
            };
            manifest.push((path, sha256.as_ref()));
        }
    }
    config.with_workloads(&manifest, budget).map_err(refused)
}

/// Read and parse the operator's file at `path`: owned by root or
/// `trusted_owner`, writable by nobody else, under directories only they can
/// change.
///
/// # Errors
///
/// Why the file is not one the authority may start from.
pub fn load(path: &str, trusted_owner: u32) -> Result<SandboxConfig, String> {
    let text = crate::secret::backend::read_operator_file(
        path,
        trusted_owner,
        MAX_FILE_BYTES,
        "--sandbox-config",
    )?;
    parse(&text).map_err(|why| format!("--sandbox-config {path}: {why}"))
}

#[cfg(test)]
mod tests {
    use super::parse;
    use dwk_proto::brokerp::sandbox::NetworkTopology;

    const HEX: &str = "abababababababababababababababababababababababababababababababab";

    /// A document with `extra`, and a bounded workspace of 64 MiB.
    fn document(extra: &str) -> String {
        bare(&format!("{extra}\n[workspace]\nquota_bytes = 67108864\n"))
    }

    /// A document with `extra` and nothing else.
    fn bare(extra: &str) -> String {
        format!(
            "schema_version = 1\n\
             runtime = \"/usr/bin/docker\"\n\
             socket = \"/run/docker.sock\"\n\
             image = \"sha256:{HEX}\"\n\
             probe_sha256 = \"{HEX}\"\n\
             {extra}"
        )
    }

    #[test]
    fn every_workspace_is_stated_bounded_or_the_evidence_harnesses_never_both() {
        use super::WorkspaceSetting;
        let config =
            parse(&document("network = \"NO_NETWORK\"\n")).unwrap_or_else(|e| unreachable!("{e}"));
        assert!(matches!(
            config.workspace(),
            WorkspaceSetting::Bounded(quota) if quota.get() == 64 << 20
        ));
        let evidence = parse(&bare(
            "network = \"NO_NETWORK\"\n[workspace]\nunverified_evidence = true\n",
        ))
        .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(evidence.workspace(), WorkspaceSetting::UnverifiedEvidence);
        for bad in [
            // No default: an operator who says nothing gets nothing.
            bare("network = \"NO_NETWORK\"\n"),
            bare("network = \"NO_NETWORK\"\n[workspace]\n"),
            bare("network = \"NO_NETWORK\"\n[workspace]\nunverified_evidence = false\n"),
            bare(
                "network = \"NO_NETWORK\"\n[workspace]\nquota_bytes = 67108864\n\
                 unverified_evidence = true\n",
            ),
            // Outside 16 MiB to 16 TiB, or not one plain decimal integer.
            bare("network = \"NO_NETWORK\"\n[workspace]\nquota_bytes = 16777215\n"),
            bare("network = \"NO_NETWORK\"\n[workspace]\nquota_bytes = 17592186044417\n"),
            bare("network = \"NO_NETWORK\"\n[workspace]\nquota_bytes = 0x4000000\n"),
            bare("network = \"NO_NETWORK\"\n[workspace]\nquota_bytes = \"64MiB\"\n"),
            bare("network = \"NO_NETWORK\"\n[workspace]\nquota_bytes = -1\n"),
            bare("network = \"NO_NETWORK\"\n[workspace]\nunverified_evidence = \"yes\"\n"),
            // The group and the mode are the contract's, never the operator's.
            bare("network = \"NO_NETWORK\"\n[workspace]\nquota_bytes = 67108864\ngroup = 1000\n"),
            bare("network = \"NO_NETWORK\"\n[workspace]\nquota_bytes = 67108864\nmode = 511\n"),
            bare("network = \"NO_NETWORK\"\nworkspace = 67108864\n"),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
        // The bounds themselves are accepted.
        for quota in [16u64 << 20, 16 << 40] {
            let text = bare(&format!(
                "network = \"NO_NETWORK\"\n[workspace]\nquota_bytes = {quota}\n"
            ));
            assert!(parse(&text).is_ok(), "{quota}");
        }
    }

    #[test]
    fn a_proxy_only_configuration_with_its_manifest_is_read_whole() {
        let text = document(&format!(
            "network = \"PROXY_ONLY\"\n\
             [egress]\nrelay_sha256 = \"{HEX}\"\nmax_tunnels = 8\n\
             max_upload_bytes = 1048576\nmax_download_bytes = 67108864\n\
             [budget]\nworkloads = 10\nseconds = 600\n\
             [executables]\n\"/usr/bin/git\" = \"{HEX}\"\n\"/usr/local/bin/pytest\" = \"{HEX}\"\n"
        ));
        let config = parse(&text).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(config.topology(), NetworkTopology::ProxyOnly);
        assert_eq!(config.executables().len(), 2);
        assert_eq!(config.workload_budget().workloads, 10);
        assert!(config.executable("/usr/bin/git").is_some());
    }

    #[test]
    fn anything_unknown_mistyped_or_missing_refuses_the_whole_file() {
        let no_network = document("network = \"NO_NETWORK\"\n");
        assert!(parse(&no_network).is_ok());
        for bad in [
            // A weakening the profile has no field for.
            document("network = \"NO_NETWORK\"\nprivileged = true\n"),
            document("network = \"NO_NETWORK\"\n[budget]\nworkloads = 1\nmounts = []\n"),
            document("network = \"HOST\"\n"),
            document("network = \"PROXY_ONLY\"\n"),
            document(&format!(
                "network = \"NO_NETWORK\"\n[egress]\nrelay_sha256 = \"{HEX}\"\n"
            )),
            document("network = \"NO_NETWORK\"\n[executables]\n\"relative/git\" = \"00\"\n"),
            document(&format!(
                "network = \"NO_NETWORK\"\n[executables]\n\"/usr/bin/git\" = 1\n\"/x\" = \"{HEX}\"\n"
            )),
            document("network = \"NO_NETWORK\"\n[budget]\nworkloads = -1\n"),
            document("network = \"NO_NETWORK\"\n[budget]\nworkloads = 0x10\n"),
            // A tag, never a digest.
            "schema_version = 1\nruntime = \"/usr/bin/docker\"\nsocket = \"/run/docker.sock\"\n\
             image = \"busybox:latest\"\nnetwork = \"NO_NETWORK\"\n"
                .to_owned(),
            "schema_version = 2\n".to_owned(),
            document("network = \"NO_NETWORK\"\n")
                .replace("schema_version = 1", "schema_version = 0x1"),
            "not toml [".to_owned(),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
    }
}

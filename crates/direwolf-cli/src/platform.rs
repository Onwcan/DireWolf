//! Development- and deployment-platform classification.
//!
//! DireWolf's security properties depend on OS facilities that differ by
//! platform: a second OS identity for the runtime, filesystem permissions on
//! `kernel.db`, and a container runtime for sandboxing.  The support tiers
//! below are the ones stated in `docs/PRODUCT_SPEC.md` §9, restated here in
//! code so `direwolf doctor` reports them rather than a reader having to infer
//! them.
//!
//! This module reports a *fact about the host*.  It does not configure, assert
//! or enforce anything, and a tier is not an assurance level: the runtime
//! `AssuranceLevel` is a kernel-side concept that arrives with the kernel
//! (M3–M5).

use std::fmt;

/// How well DireWolf's security model is supported on a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SupportTier {
    /// Every mechanism the architecture relies on is available natively.
    Full,
    /// Supported; the container sandbox runs inside a Linux VM.
    FullViaVm,
    /// A Linux environment hosted by Windows. Supported; this is the
    /// recommended way to develop DireWolf on a Windows machine.
    Wsl2,
    /// Runs, but some OS mechanisms the design relies on are absent or
    /// differently shaped. Never silent about it.
    ReducedAssurance,
    /// Not a platform the project has evaluated.
    Unknown,
}

impl SupportTier {
    /// One line, suitable for a terminal, stating the tier and why.
    pub(crate) fn explain(self) -> &'static str {
        match self {
            Self::Full => "supported; all required OS mechanisms are available natively",
            Self::FullViaVm => "supported; the container sandbox runs in a Linux VM",
            Self::Wsl2 => "supported; this is the recommended Windows development path",
            Self::ReducedAssurance => {
                "runs, but some OS mechanisms the design relies on are absent or differ"
            }
            Self::Unknown => "not evaluated by the project",
        }
    }
}

impl fmt::Display for SupportTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Full => "full",
            Self::FullViaVm => "full (via VM)",
            Self::Wsl2 => "full (WSL2)",
            Self::ReducedAssurance => "reduced assurance",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// Classify a host from its OS name and whether it is a WSL kernel.
///
/// Split out from [`detect`] as a pure function so the mapping is testable on
/// any host, rather than only on the one the tests happen to run on.
pub(crate) fn classify(target_os: &str, is_wsl: bool) -> SupportTier {
    match target_os {
        "linux" if is_wsl => SupportTier::Wsl2,
        "linux" => SupportTier::Full,
        "macos" => SupportTier::FullViaVm,
        // Native Windows lacks the uid model the two-identity install assumes,
        // and `openat2`-equivalent path resolution differs.  It is a real
        // target and it is loudly labelled.
        "windows" => SupportTier::ReducedAssurance,
        _ => SupportTier::Unknown,
    }
}

/// Classify the host this binary is running on.
pub(crate) fn detect() -> SupportTier {
    classify(std::env::consts::OS, is_wsl())
}

/// True when the running Linux kernel is a WSL kernel.
///
/// Microsoft's kernel build string contains "microsoft" for both WSL1 and
/// WSL2.  A false negative costs only a less specific label.
fn is_wsl() -> bool {
    if std::env::consts::OS != "linux" {
        return false;
    }
    std::fs::read_to_string("/proc/version")
        .map(|v| v.to_ascii_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{SupportTier, classify};

    #[test]
    fn linux_is_full() {
        assert_eq!(classify("linux", false), SupportTier::Full);
    }

    #[test]
    fn wsl_is_reported_as_wsl_not_as_plain_linux() {
        assert_eq!(classify("linux", true), SupportTier::Wsl2);
    }

    #[test]
    fn macos_is_full_via_vm() {
        assert_eq!(classify("macos", false), SupportTier::FullViaVm);
    }

    #[test]
    fn native_windows_is_never_reported_as_full() {
        let tier = classify("windows", false);
        assert_eq!(tier, SupportTier::ReducedAssurance);
        assert_ne!(tier, SupportTier::Full);
    }

    #[test]
    fn unknown_os_is_not_silently_promoted() {
        assert_eq!(classify("plan9", false), SupportTier::Unknown);
    }

    #[test]
    fn every_tier_explains_itself() {
        for tier in [
            SupportTier::Full,
            SupportTier::FullViaVm,
            SupportTier::Wsl2,
            SupportTier::ReducedAssurance,
            SupportTier::Unknown,
        ] {
            assert!(!tier.explain().is_empty());
            assert!(!tier.to_string().is_empty());
        }
    }
}

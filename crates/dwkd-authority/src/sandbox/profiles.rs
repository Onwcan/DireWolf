//! The hygiene profiles whose ADRs are **Proposed, not accepted** (M5e.5):
//! npm's (ADR-0054 §7) and pip's (ADR-0055 §8), which the evidence must
//! exercise through the real authority, broker and launcher before either can
//! be accepted.
//!
//! **None is on in production, and nothing turns one on but the operator's
//! start-up option.** The value is [`HygieneProfiles::NONE`] unless
//! `dwkd-authority serve --allow-unaccepted-hygiene-profile npm|pip` names a
//! profile, and the server attaches it to the operator's execution environment
//! only when that environment is the evidence harness's own (`[workspace]
//! unverified_evidence`, which every broker refuses unless its operator
//! acknowledged it) -- logging `REDUCED ASSURANCE`. No request, variable,
//! policy pack or workspace file carries it (TX060). With [`HygieneProfiles::NONE`]
//! every decision is today's: the state layer gives the obligation's pure
//! decision (`resource::exec::hygiene`) its own copy of the value, and that
//! decision is held to today's by a table test over every input its tests use.
//!
//! The change that implements an ADR's acceptance removes the option and the
//! profile's entry here, and keeps the profile unconditionally.

/// A hygiene profile whose ADR is Proposed, not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnacceptedProfile {
    /// npm's (ADR-0054): `npm ci` and `npm install` of registry names.
    Npm,
    /// pip's (ADR-0055): `pip install` of named wheels.
    Pip,
}

impl UnacceptedProfile {
    /// Every profile, in a stable order.
    pub const ALL: [Self; 2] = [Self::Npm, Self::Pip];

    /// Its name on the command line and in the log.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pip => "pip",
        }
    }

    /// The profile `text` names exactly, or none: never a prefix, a case
    /// variant or a default.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == text)
    }
}

/// Which unaccepted profiles this authority keeps. [`Self::NONE`] in every
/// production configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HygieneProfiles {
    npm: bool,
    pip: bool,
}

impl HygieneProfiles {
    /// No unaccepted profile: production's, and the default.
    pub const NONE: Self = Self {
        npm: false,
        pip: false,
    };

    /// The same, with `profile` kept as well.
    #[must_use]
    pub const fn with(self, profile: UnacceptedProfile) -> Self {
        match profile {
            UnacceptedProfile::Npm => Self { npm: true, ..self },
            UnacceptedProfile::Pip => Self { pip: true, ..self },
        }
    }

    /// Whether `profile` is kept.
    #[must_use]
    pub const fn keeps(self, profile: UnacceptedProfile) -> bool {
        match profile {
            UnacceptedProfile::Npm => self.npm,
            UnacceptedProfile::Pip => self.pip,
        }
    }

    /// Whether none is kept.
    #[must_use]
    pub const fn is_none(self) -> bool {
        !self.npm && !self.pip
    }

    /// The kept profiles' names, in a stable order.
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        UnacceptedProfile::ALL
            .into_iter()
            .filter(|p| self.keeps(*p))
            .map(UnacceptedProfile::as_str)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{HygieneProfiles, UnacceptedProfile};

    #[test]
    fn none_is_the_default_and_keeps_nothing() {
        assert_eq!(HygieneProfiles::default(), HygieneProfiles::NONE);
        assert!(HygieneProfiles::NONE.is_none());
        for profile in UnacceptedProfile::ALL {
            assert!(!HygieneProfiles::NONE.keeps(profile), "{profile:?}");
        }
        assert!(HygieneProfiles::NONE.names().is_empty());
    }

    #[test]
    fn each_profile_is_kept_only_when_named() {
        let npm = HygieneProfiles::NONE.with(UnacceptedProfile::Npm);
        assert!(npm.keeps(UnacceptedProfile::Npm) && !npm.keeps(UnacceptedProfile::Pip));
        let pip = HygieneProfiles::NONE.with(UnacceptedProfile::Pip);
        assert!(pip.keeps(UnacceptedProfile::Pip) && !pip.keeps(UnacceptedProfile::Npm));
        let both = npm.with(UnacceptedProfile::Pip);
        assert_eq!(both.names(), ["npm", "pip"]);
        assert!(!both.is_none());
    }

    #[test]
    fn only_an_exact_name_parses() {
        assert_eq!(
            UnacceptedProfile::parse("npm"),
            Some(UnacceptedProfile::Npm)
        );
        assert_eq!(
            UnacceptedProfile::parse("pip"),
            Some(UnacceptedProfile::Pip)
        );
        for other in [
            "", "NPM", "Pip", "npx", "pip3", "npm ", " npm", "all", "yarn", "cargo",
        ] {
            assert_eq!(UnacceptedProfile::parse(other), None, "{other:?}");
        }
    }
}

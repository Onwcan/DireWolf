//! What this host can hold, and whether a model is likely to fit
//! (ADR-0072, Proposed).
//!
//! **Facts, read-only.** The CPU architecture and the number of hardware
//! threads from the standard library; total and available memory from
//! `/proc/meminfo` on Linux. Nothing else is probed: no GPU runtime is
//! loaded and no vendor tool is run, so graphics memory is UNKNOWN unless the
//! operator states it (`--vram-gib`), and an operator's statement replaces a
//! fact without replacing any check.
//!
//! **An estimate, never a promise.** The memory a GGUF model needs is its
//! weights, plus its key-value cache at the context asked for (two tensors,
//! 16-bit, per layer: `2 x layers x context x kv-width x 2` bytes, where the
//! kv-width is the embedding width scaled by the key-value heads), plus a
//! tenth of the weights and 512 MiB of runtime overhead. Without the layer
//! count, the widths or the head counts the cache cannot be estimated, and
//! the answer is UNKNOWN -- unless the weights alone already exceed what the
//! host has, which is DOES_NOT_FIT. Integer arithmetic only.

use super::library::Manifest;

/// One gibibyte.
const GIB: u64 = 1 << 30;
/// Runtime overhead beyond a tenth of the weights.
const OVERHEAD_BYTES: u64 = 512 << 20;

/// The host, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Facts {
    pub(crate) arch: &'static str,
    pub(crate) os: &'static str,
    pub(crate) threads: Option<u64>,
    pub(crate) ram_total: Option<u64>,
    pub(crate) ram_available: Option<u64>,
    /// Graphics memory: only ever what the operator said.
    pub(crate) vram: Option<u64>,
}

/// `MemTotal` and `MemAvailable` from `/proc/meminfo`'s text, in bytes.
pub(crate) fn meminfo(text: &str) -> (Option<u64>, Option<u64>) {
    let field = |name: &str| {
        text.lines().find_map(|line| {
            let rest = line.strip_prefix(name)?.strip_prefix(':')?.trim();
            let kib = rest.strip_suffix(" kB")?.trim().parse::<u64>().ok()?;
            kib.checked_mul(1024)
        })
    };
    (field("MemTotal"), field("MemAvailable"))
}

/// Read this host's facts; `vram_gib` is the operator's statement, if any.
pub(crate) fn detect(vram_gib: Option<u64>) -> Facts {
    let (ram_total, ram_available) = std::fs::read_to_string("/proc/meminfo")
        .map(|text| meminfo(&text))
        .unwrap_or((None, None));
    Facts {
        arch: std::env::consts::ARCH,
        os: std::env::consts::OS,
        threads: std::thread::available_parallelism()
            .ok()
            .and_then(|n| u64::try_from(n.get()).ok()),
        ram_total,
        ram_available,
        vram: vram_gib.and_then(|g| g.checked_mul(GIB)),
    }
}

/// Whether a model is likely to fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Headroom {
    /// At most three quarters of the memory it would use.
    Fits,
    /// At most nine tenths.
    LikelyFits,
    /// At most eleven tenths: it may, or may not.
    MayNotFit,
    /// More.
    DoesNotFit,
    /// A fact the estimate needs is missing.
    Unknown,
}

impl Headroom {
    pub(crate) const fn word(self) -> &'static str {
        match self {
            Self::Fits => "FITS",
            Self::LikelyFits => "LIKELY_FITS",
            Self::MayNotFit => "MAY_NOT_FIT",
            Self::DoesNotFit => "DOES_NOT_FIT",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// An estimate and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Estimate {
    pub(crate) fit: Headroom,
    pub(crate) needed: Option<u64>,
    pub(crate) budget: Option<u64>,
    /// `GPU` (the operator's stated graphics memory) or `RAM`.
    pub(crate) place: &'static str,
    pub(crate) why: String,
}

/// The context an estimate is made at: what was asked, at most the
/// model's own.
fn effective(m: &Manifest, context: u64) -> u64 {
    m.context_length.map_or(context, |max| context.min(max))
}

/// The key-value cache at `context` tokens, if the facts allow it.
fn kv_cache(m: &Manifest, context: u64) -> Option<u64> {
    let layers = m.block_count?;
    let width = m.embedding_length?;
    let heads = m.head_count.filter(|h| *h > 0)?;
    let kv_heads = m.head_count_kv.unwrap_or(heads);
    let kv_width = width.checked_mul(kv_heads)?.checked_div(heads)?;
    let context = effective(m, context);
    2u64.checked_mul(layers)?
        .checked_mul(context)?
        .checked_mul(kv_width)?
        .checked_mul(2)
}

/// The fit of `needed` bytes in `budget`.
fn ratio(needed: u64, budget: u64) -> Headroom {
    let (n, b) = (u128::from(needed), u128::from(budget));
    if n * 100 <= b * 75 {
        Headroom::Fits
    } else if n * 100 <= b * 90 {
        Headroom::LikelyFits
    } else if n * 100 <= b * 110 {
        Headroom::MayNotFit
    } else {
        Headroom::DoesNotFit
    }
}

fn gib(bytes: u64) -> String {
    let whole = bytes.checked_div(GIB).unwrap_or(0);
    let tenths = (bytes % GIB)
        .checked_mul(10)
        .and_then(|t| t.checked_div(GIB))
        .unwrap_or(0);
    format!("{whole}.{tenths} GiB")
}

/// Estimate whether `m` fits this host at `context` tokens.
pub(crate) fn estimate(m: &Manifest, context: u64, facts: &Facts) -> Estimate {
    let weights = m.weight_bytes();
    let (budget, place) = match (facts.vram, facts.ram_available) {
        (Some(v), _) => (Some(v), "GPU"),
        (None, Some(r)) => (Some(r), "RAM"),
        (None, None) => (None, "RAM"),
    };
    let Some(budget) = budget else {
        return Estimate {
            fit: Headroom::Unknown,
            needed: None,
            budget: None,
            place,
            why: "this host's available memory is not known here, and none was stated".to_owned(),
        };
    };
    if m.format != "GGUF" {
        return Estimate {
            fit: if weights > budget {
                Headroom::DoesNotFit
            } else {
                Headroom::Unknown
            },
            needed: None,
            budget: Some(budget),
            place,
            why: format!(
                "{} weights ({}); no local backend for {} in this build, so no runtime size is \
                 estimated",
                m.format,
                gib(weights),
                m.format
            ),
        };
    }
    let Some(kv) = kv_cache(m, context) else {
        return Estimate {
            fit: if weights > budget {
                Headroom::DoesNotFit
            } else {
                Headroom::Unknown
            },
            needed: None,
            budget: Some(budget),
            place,
            why: format!(
                "weights {}; the key-value cache cannot be estimated without the layer count, \
                 widths and head counts, so a fit is never promised from the file size",
                gib(weights)
            ),
        };
    };
    let overhead = weights
        .checked_div(10)
        .unwrap_or(0)
        .saturating_add(OVERHEAD_BYTES);
    let needed = weights.saturating_add(kv).saturating_add(overhead);
    Estimate {
        fit: ratio(needed, budget),
        needed: Some(needed),
        budget: Some(budget),
        place,
        why: format!(
            "weights {} + key-value cache {} at {} tokens + overhead {} = {} of {} {place}",
            gib(weights),
            gib(kv),
            effective(m, context),
            gib(overhead),
            gib(needed),
            gib(budget)
        ),
    }
}

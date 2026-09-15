//! ECMAScript `Number::toString`, as RFC 8785 §3.2.2.3 requires.
//!
//! Two steps, and the first is where implementations get it wrong.
//!
//! **Choosing the digits.** ECMA-262 §7.1.12.1 wants the fewest significant
//! digits `k` that read back as the same double, and — RFC 8785 mandates the
//! spec's "Note 2" — among the `k`-digit decimals that do, the one closest to
//! the exact binary value, with exact ties going to the even digit. Rust's
//! `{:e}` gives the right `k` but does not promise that tie-break:
//! `1424953923781206.25` has two equally close 17-digit neighbours, and `{:e}`
//! picks `…063` where the specification requires `…062` (RFC 8785 Appendix B,
//! the "round to even" row, which caught exactly this). Rust's `{:.Ne}` *does*
//! round exact ties to even, so the digits are re-derived at precision `k`; that
//! value is the closest `k`-digit decimal by construction, and is used whenever
//! it round-trips. Where it does not — possible only beside a power of two,
//! where the rounding interval is asymmetric — the shortest form is used, which
//! is the only `k`-digit candidate that does.
//!
//! **Laying them out.** Mechanical; below.
//!
//! Verified against every sample in RFC 8785 Appendix B and against doubles
//! serialised by V8 (`tests/protocol/vectors/numbers.json`).

/// Format a finite double the way ECMAScript's `String(x)` does.
///
/// Returns `None` for NaN and infinities, which JSON cannot carry. `-0` formats
/// as `"0"`.
#[must_use]
pub fn format_es(x: f64) -> Option<String> {
    if !x.is_finite() {
        return None;
    }
    if x == 0.0 {
        return Some("0".to_owned());
    }
    let magnitude = x.abs();
    let (shortest_digits, shortest_exponent) = split_scientific(&format!("{magnitude:e}"))?;
    let k = shortest_digits.len();
    let precision = k.checked_sub(1)?;
    let tie_even = format!("{magnitude:.precision$e}");
    let (digits, exponent) = if tie_even.parse::<f64>().ok() == Some(magnitude) {
        split_scientific(&tie_even)?
    } else {
        (shortest_digits, shortest_exponent)
    };

    let k = i32::try_from(digits.len()).ok()?; // significant digits
    let n = exponent.checked_add(1)?; // position of the decimal point
    let digits = digits.as_str();

    let mut out = String::new();
    if x.is_sign_negative() {
        out.push('-');
    }
    if k <= n && n <= 21 {
        // Integer-valued: digits then zeros.
        out.push_str(digits);
        out.extend(std::iter::repeat_n('0', usize::try_from(n - k).ok()?));
    } else if 0 < n && n <= 21 {
        // Decimal point inside the digits.
        let split = usize::try_from(n).ok()?;
        out.push_str(digits.get(..split)?);
        out.push('.');
        out.push_str(digits.get(split..)?);
    } else if -6 < n && n <= 0 {
        // Small magnitude: "0." and leading zeros.
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', usize::try_from(-n).ok()?));
        out.push_str(digits);
    } else {
        // Exponential form, with an explicit exponent sign.
        let e = n - 1;
        let (first, rest) = digits.split_at(1);
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        out.push('e');
        out.push(if e < 0 { '-' } else { '+' });
        out.push_str(&e.unsigned_abs().to_string());
    }
    Some(out)
}

/// Split Rust scientific notation (`"1.2345e-7"`) into significant digits with
/// trailing zeros removed (`"12345"`) and the exponent (`-7`).
fn split_scientific(sci: &str) -> Option<(String, i32)> {
    let (mantissa, exponent) = sci.split_once('e')?;
    let exponent: i32 = exponent.parse().ok()?;
    // Rust always normalises the mantissa to one leading digit (a rounding carry
    // yields "1.0e1", not "10e0"), so trimming trailing zeros is sufficient.
    let mut digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    Some((digits, exponent))
}

#[cfg(test)]
mod tests {
    use super::format_es;

    /// RFC 8785 Appendix B, Table 1, rows with a JSON representation.
    /// Source: <https://www.rfc-editor.org/rfc/rfc8785.txt>, Appendix B.
    const RFC_8785_APPENDIX_B: &[(u64, &str)] = &[
        (0x0000_0000_0000_0000, "0"),
        (0x8000_0000_0000_0000, "0"),
        (0x0000_0000_0000_0001, "5e-324"),
        (0x8000_0000_0000_0001, "-5e-324"),
        (0x7fef_ffff_ffff_ffff, "1.7976931348623157e+308"),
        (0xffef_ffff_ffff_ffff, "-1.7976931348623157e+308"),
        (0x4340_0000_0000_0000, "9007199254740992"),
        (0xc340_0000_0000_0000, "-9007199254740992"),
        (0x4430_0000_0000_0000, "295147905179352830000"),
        (0x44b5_2d02_c7e1_4af5, "9.999999999999997e+22"),
        (0x44b5_2d02_c7e1_4af6, "1e+23"),
        (0x44b5_2d02_c7e1_4af7, "1.0000000000000001e+23"),
        (0x444b_1ae4_d6e2_ef4e, "999999999999999700000"),
        (0x444b_1ae4_d6e2_ef4f, "999999999999999900000"),
        (0x444b_1ae4_d6e2_ef50, "1e+21"),
        (0x3eb0_c6f7_a0b5_ed8c, "9.999999999999997e-7"),
        (0x3eb0_c6f7_a0b5_ed8d, "0.000001"),
        (0x41b3_de43_5555_5553, "333333333.3333332"),
        (0x41b3_de43_5555_5554, "333333333.33333325"),
        (0x41b3_de43_5555_5555, "333333333.3333333"),
        (0x41b3_de43_5555_5556, "333333333.3333334"),
        (0x41b3_de43_5555_5557, "333333333.33333343"),
        (0xbecb_f647_612f_3696, "-0.0000033333333333333333"),
        (0x4314_3ff3_c1cb_0959, "1424953923781206.2"),
    ];

    #[test]
    fn rfc_8785_appendix_b_samples() {
        for &(bits, expected) in RFC_8785_APPENDIX_B {
            let x = f64::from_bits(bits);
            assert_eq!(
                format_es(x).as_deref(),
                Some(expected),
                "IEEE 754 {bits:016x}"
            );
        }
    }

    #[test]
    fn rfc_8785_appendix_b_non_finite_rows_are_errors() {
        assert_eq!(format_es(f64::from_bits(0x7fff_ffff_ffff_ffff)), None); // NaN
        assert_eq!(format_es(f64::from_bits(0x7ff0_0000_0000_0000)), None); // Infinity
    }
}

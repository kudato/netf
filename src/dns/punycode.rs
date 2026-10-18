//! IDNA for `domain:`. An ASCII label becomes lowercase, and a label with
//! non-ASCII characters becomes `xn--` and RFC 3492 punycode. netf does no
//! NFC or UTS 46 mapping, because the tables would be larger than the rest
//! of the binary.
//!
//! A non-ASCII label is lowered with [`char::to_lowercase`], which covers
//! what people type, such as `Παράδειγμα.Δοκιμή`. The rest of UTS 46 is left to the
//! DNS: width folding, NFC, and the disallowed code points. A name that is
//! not valid IDNA does not resolve. Before this module runs, the query
//! parser checks the label lengths and the allowed characters of the name.

use std::fmt;

/// The punycode parameters of RFC 3492, section 5.
const BASE: u32 = 36;
const T_MIN: u32 = 1;
const T_MAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 0x80;

/// The prefix of an encoded label: the ACE prefix of RFC 5890.
const ACE_PREFIX: &str = "xn--";

/// A label that punycode cannot represent.
///
/// The arithmetic of RFC 3492 overflows only for a label of thousands of
/// characters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Overflow;

impl fmt::Display for Overflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid domain name")
    }
}

impl std::error::Error for Overflow {}

/// Converts a domain to the form sent to DNS: lowercase, with each
/// non-ASCII label as `xn--` punycode.
///
/// The function drops a trailing dot, which stands for the root: `Example.COM.`
/// gives `example.com`.
///
/// # Errors
///
/// Returns [`Overflow`] if a label is too long for punycode.
pub(crate) fn to_ascii(domain: &str) -> Result<String, Overflow> {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    let mut out = String::with_capacity(domain.len());
    for (i, label) in domain.split('.').enumerate() {
        if i > 0 {
            out.push('.');
        }
        if label.is_ascii() {
            out.push_str(&label.to_ascii_lowercase());
        } else {
            let lowered: Vec<char> = label.chars().flat_map(char::to_lowercase).collect();
            out.push_str(ACE_PREFIX);
            out.push_str(&encode(&lowered)?);
        }
    }
    Ok(out)
}

/// Encodes code points with the punycode algorithm of RFC 3492, section
/// 6.3, without the `xn--` prefix.
///
/// Basic code points keep their case.
///
/// # Errors
///
/// Returns [`Overflow`] if the arithmetic overflows `u32`.
pub(crate) fn encode(input: &[char]) -> Result<String, Overflow> {
    let mut output: String = input.iter().filter(|c| c.is_ascii()).collect();
    let basic = u32::try_from(output.len()).map_err(|_| Overflow)?;
    if basic > 0 {
        output.push('-');
    }
    let total = u32::try_from(input.len()).map_err(|_| Overflow)?;

    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut handled = basic;
    while handled < total {
        // The smallest code point not handled yet. Such a point exists
        // while `handled < total`.
        let m = input
            .iter()
            .map(|&c| u32::from(c))
            .filter(|&c| c >= n)
            .min()
            .ok_or(Overflow)?;
        delta = (m - n)
            .checked_mul(handled + 1)
            .and_then(|d| d.checked_add(delta))
            .ok_or(Overflow)?;
        n = m;
        for &c in input {
            let c = u32::from(c);
            if c < n {
                delta = delta.checked_add(1).ok_or(Overflow)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = threshold(k, bias);
                    if q < t {
                        break;
                    }
                    output.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1).ok_or(Overflow)?;
        n = n.checked_add(1).ok_or(Overflow)?;
    }
    Ok(output)
}

/// Returns the threshold `t` for position `k`, from RFC 3492, section 6.3.
fn threshold(k: u32, bias: u32) -> u32 {
    if k <= bias {
        T_MIN
    } else if k >= bias + T_MAX {
        T_MAX
    } else {
        k - bias
    }
}

/// Adapts the bias, as RFC 3492, section 6.1 defines it.
fn adapt(delta: u32, points: u32, first: bool) -> u32 {
    let mut delta = if first { delta / DAMP } else { delta / 2 };
    delta += delta / points;
    let mut k = 0;
    while delta > ((BASE - T_MIN) * T_MAX) / 2 {
        delta /= BASE - T_MIN;
        k += BASE;
    }
    k + (BASE - T_MIN + 1) * delta / (delta + SKEW)
}

/// Returns the basic code point of a digit: `a` to `z` for 0 to 25, and
/// `0` to `9` for 26 to 35.
fn digit(d: u32) -> char {
    let byte = match d {
        0..=25 => b'a' + d as u8,
        _ => b'0' + (d - 26) as u8,
    };
    char::from(byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the input of an RFC 3492 sample from its code points.
    fn points(codes: &[u32]) -> Vec<char> {
        codes
            .iter()
            .map(|&c| char::from_u32(c).expect("code point"))
            .collect()
    }

    /// Samples from RFC 3492, section 7.1.
    #[test]
    fn rfc3492_samples() {
        let samples: &[(&[u32], &str)] = &[
            // (A) Arabic (Egyptian)
            (
                &[
                    0x0644, 0x064A, 0x0647, 0x0645, 0x0627, 0x0628, 0x062A, 0x0643, 0x0644, 0x0645,
                    0x0648, 0x0634, 0x0639, 0x0631, 0x0628, 0x064A, 0x061F,
                ],
                "egbpdaj6bu4bxfgehfvwxn",
            ),
            // (B) Chinese (simplified)
            (
                &[
                    0x4ED6, 0x4EEC, 0x4E3A, 0x4EC0, 0x4E48, 0x4E0D, 0x8BF4, 0x4E2D, 0x6587,
                ],
                "ihqwcrb4cv8a8dqg056pqjye",
            ),
            // (C) Chinese (traditional)
            (
                &[
                    0x4ED6, 0x5011, 0x7232, 0x4EC0, 0x9EBD, 0x4E0D, 0x8AAA, 0x4E2D, 0x6587,
                ],
                "ihqwctvzc91f659drss3x8bo0yb",
            ),
            // (D) Czech
            (
                &[
                    0x0050, 0x0072, 0x006F, 0x010D, 0x0070, 0x0072, 0x006F, 0x0073, 0x0074, 0x011B,
                    0x006E, 0x0065, 0x006D, 0x006C, 0x0075, 0x0076, 0x00ED, 0x010D, 0x0065, 0x0073,
                    0x006B, 0x0079,
                ],
                "Proprostnemluvesky-uyb24dma41a",
            ),
            // (E) Hebrew
            (
                &[
                    0x05DC, 0x05DE, 0x05D4, 0x05D4, 0x05DD, 0x05E4, 0x05E9, 0x05D5, 0x05D8, 0x05DC,
                    0x05D0, 0x05DE, 0x05D3, 0x05D1, 0x05E8, 0x05D9, 0x05DD, 0x05E2, 0x05D1, 0x05E8,
                    0x05D9, 0x05EA,
                ],
                "4dbcagdahymbxekheh6e0a7fei0b",
            ),
            // (G) Japanese (kanji and hiragana)
            (
                &[
                    0x306A, 0x305C, 0x307F, 0x3093, 0x306A, 0x65E5, 0x672C, 0x8A9E, 0x3092, 0x8A71,
                    0x3057, 0x3066, 0x304F, 0x308C, 0x306A, 0x3044, 0x306E, 0x304B,
                ],
                "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa",
            ),
            // (L) 3<nen>B<gumi><kinpachi><sensei>
            (
                &[
                    0x0033, 0x5E74, 0x0042, 0x7D44, 0x91D1, 0x516B, 0x5148, 0x751F,
                ],
                "3B-ww4c5e180e575a65lsy2b",
            ),
            // (M) <amuro><namie>-with-SUPER-MONKEYS
            (
                &[
                    0x5B89, 0x5BA4, 0x5948, 0x7F8E, 0x6075, 0x002D, 0x0077, 0x0069, 0x0074, 0x0068,
                    0x002D, 0x0053, 0x0055, 0x0050, 0x0045, 0x0052, 0x002D, 0x004D, 0x004F, 0x004E,
                    0x004B, 0x0045, 0x0059, 0x0053,
                ],
                "-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n",
            ),
            // (N) Hello-Another-Way-<sorezore><no><basho>
            (
                &[
                    0x0048, 0x0065, 0x006C, 0x006C, 0x006F, 0x002D, 0x0041, 0x006E, 0x006F, 0x0074,
                    0x0068, 0x0065, 0x0072, 0x002D, 0x0057, 0x0061, 0x0079, 0x002D, 0x305D, 0x308C,
                    0x305E, 0x308C, 0x306E, 0x5834, 0x6240,
                ],
                "Hello-Another-Way--fc4qua05auwb3674vfr0b",
            ),
            // (O) <hitotsu><yane><no><shita>2
            (
                &[
                    0x3072, 0x3068, 0x3064, 0x5C4B, 0x6839, 0x306E, 0x4E0B, 0x0032,
                ],
                "2-u9tlzr9756bt3uc0v",
            ),
            // (P) Maji<de>Koi<suru>5<byou><mae>
            (
                &[
                    0x004D, 0x0061, 0x006A, 0x0069, 0x3067, 0x004B, 0x006F, 0x0069, 0x3059, 0x308B,
                    0x0035, 0x79D2, 0x524D,
                ],
                "MajiKoi5-783gue6qz075azm5e",
            ),
            // (Q) <pafii>de<runba>
            (
                &[
                    0x30D1, 0x30D5, 0x30A3, 0x30FC, 0x0064, 0x0065, 0x30EB, 0x30F3, 0x30D0,
                ],
                "de-jg4avhby1noc0d",
            ),
            // (R) <sono><supiido><de>
            (
                &[0x305D, 0x306E, 0x30B9, 0x30D4, 0x30FC, 0x30C9, 0x3067],
                "d9juau41awczczp",
            ),
            // (S) -> $1.00 <-
            (
                &[
                    0x002D, 0x003E, 0x0020, 0x0024, 0x0031, 0x002E, 0x0030, 0x0030, 0x0020, 0x003C,
                    0x002D,
                ],
                "-> $1.00 <--",
            ),
        ];
        for (codes, expected) in samples {
            assert_eq!(encode(&points(codes)).unwrap(), *expected);
        }
    }

    #[test]
    fn domains() {
        assert_eq!(to_ascii("Ex.TEST").unwrap(), "ex.test");
        assert_eq!(to_ascii("ex.test.").unwrap(), "ex.test");
        assert_eq!(
            to_ascii("παράδειγμα.δοκιμή").unwrap(),
            "xn--hxajbheg2az3al.xn--jxalpdlp"
        );
        assert_eq!(
            to_ascii("ΠΑΡΆΔΕΙΓΜΑ.ΔΟΚΙΜΉ").unwrap(),
            "xn--hxajbheg2az3al.xn--jxalpdlp"
        );
        assert_eq!(to_ascii("café.test").unwrap(), "xn--caf-dma.test");
        assert_eq!(
            to_ascii("www.Bücher.example").unwrap(),
            "www.xn--bcher-kva.example"
        );
    }

    #[test]
    fn huge_labels_overflow() {
        // The encoder multiplies the jump to a code point by the number of
        // points already handled, so the highest code point after 4000 basic
        // ones overflows `u32`.
        let mut label: Vec<char> = std::iter::repeat_n('a', 4000).collect();
        label.push('\u{10FFFF}');
        assert_eq!(encode(&label), Err(Overflow));
    }
}

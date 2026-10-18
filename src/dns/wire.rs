//! DNS messages for DoH: one A or AAAA question with RD set and an id from
//! [`random_id`].
//!
//! The parser checks the id of the answer. RCODE 0 gives every A or AAAA
//! record of the answer section, and RCODE 3 is NXDOMAIN. The parser follows
//! compression pointers with a guard against loops.
//!
//! This module holds only what netf needs of RFC 1035: building a query and
//! reading the addresses out of the reply. The parser does not compare the
//! owners of the answer records with the question, so it follows a CNAME
//! chain inside the answer by taking every record of the asked type. It
//! ignores TTLs, because netf does not cache answers between runs.
//!
//! The reply comes from a server that netf does not control, so every read
//! is bounds-checked, and a name may not loop through compression pointers.
//! A pointer must point before itself, and a name is at most 255 octets and
//! 128 pointers long.

use std::{
    fmt,
    hash::{BuildHasher as _, Hasher as _},
    net::{Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicU32, Ordering},
};

/// The longest name on the wire, from RFC 1035, section 2.3.4.
const MAX_NAME: usize = 255;
/// The longest label, from RFC 1035, section 2.3.4.
const MAX_LABEL: usize = 63;
/// The most compression pointers followed in one name. A name of 255
/// octets cannot need more, so more pointers mean a loop.
const MAX_POINTERS: usize = 128;
/// The length of the message header.
const HEADER: usize = 12;
/// The class IN.
const CLASS_IN: u16 = 1;

/// The type of the question.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QType {
    /// IPv4 addresses.
    A,
    /// IPv6 addresses.
    Aaaa,
}

impl QType {
    /// Returns the type code: 1 or 28.
    fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

/// What the server answered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Reply {
    /// RCODE 0: the addresses of the asked type, possibly none.
    Addresses {
        /// The addresses from A records.
        v4: Vec<Ipv4Addr>,
        /// The addresses from AAAA records.
        v6: Vec<Ipv6Addr>,
    },
    /// RCODE 3: the name does not exist.
    NxDomain,
    /// Another RCODE. [`rcode_name`] gives its name.
    Error(u8),
}

/// A message that netf cannot use: a name it cannot encode, or a reply that
/// is broken or answers another query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WireError {
    /// The name is empty or over 255 octets, or it has an empty label or a
    /// label over 63 octets.
    InvalidName,
    /// The reply is cut short or its structure is broken. The text says
    /// where.
    Malformed(&'static str),
    /// The reply has another id, so it answers another query.
    IdMismatch,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => f.write_str("invalid domain name"),
            Self::Malformed(what) => write!(f, "malformed answer: {what}"),
            Self::IdMismatch => f.write_str("answer to another query"),
        }
    }
}

impl std::error::Error for WireError {}

/// Returns the name of a response code for messages, such as `SERVFAIL`,
/// `REFUSED`, or `RCODE 9`.
pub(crate) fn rcode_name(rcode: u8) -> String {
    match rcode {
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        _ => format!("RCODE {rcode}"),
    }
}

/// Returns a query id for a DoH request.
///
/// Each call hashes a counter with a new `RandomState`. The counter can
/// wrap, and the 16-bit ids can repeat. HTTP matches each response to its
/// request, so the id provides an extra check on the DNS reply.
pub(crate) fn random_id() -> u16 {
    // Use 32 bits for MIPS targets without 64-bit atomics.
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let mut hasher = std::hash::RandomState::new().build_hasher();
    hasher.write_u64(u64::from(COUNTER.fetch_add(1, Ordering::Relaxed)));
    // The truncation is intended, because any 16 bits of the hash will do.
    hasher.finish() as u16
}

/// Builds a query for `name` of type `qtype` with recursion desired.
///
/// # Errors
///
/// Returns [`WireError::InvalidName`] if `name` cannot be encoded.
pub(crate) fn query(id: u16, name: &str, qtype: QType) -> Result<Vec<u8>, WireError> {
    let mut message = Vec::with_capacity(HEADER + name.len() + 6);
    message.extend_from_slice(&id.to_be_bytes());
    // QR = 0, opcode QUERY, RD = 1.
    message.extend_from_slice(&0x0100_u16.to_be_bytes());
    // One question, no other records.
    message.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    encode_name(&mut message, name)?;
    message.extend_from_slice(&qtype.code().to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(message)
}

/// Appends `name` in wire form: length-prefixed labels and the root.
///
/// # Errors
///
/// Returns [`WireError::InvalidName`] if `name` is empty or too long, or if
/// a label is empty or too long.
fn encode_name(out: &mut Vec<u8>, name: &str) -> Result<(), WireError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    // The labels, their length octets, and the root octet.
    if name.is_empty() || name.len() + 2 > MAX_NAME {
        return Err(WireError::InvalidName);
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL {
            return Err(WireError::InvalidName);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Reads the reply to a query made with [`query`]`(id, name, qtype)`.
///
/// The question, if the server repeats it, must be the one asked. The
/// parser takes only records of the asked type and class IN.
///
/// # Errors
///
/// Returns [`WireError::IdMismatch`] if the reply has another id. Returns
/// [`WireError::Malformed`] if the message is not a response, is cut short,
/// holds a broken name, repeats another question, or holds an address of a
/// wrong length.
pub(crate) fn parse(message: &[u8], id: u16, name: &str, qtype: QType) -> Result<Reply, WireError> {
    let mut reader = Reader { message, pos: 0 };
    if reader.u16()? != id {
        return Err(WireError::IdMismatch);
    }
    let flags = reader.u16()?;
    if flags & 0x8000 == 0 {
        return Err(WireError::Malformed("not a response"));
    }
    let questions = reader.u16()?;
    let answers = reader.u16()?;
    // The parser does not read authority and additional records.
    reader.skip(4)?;

    for _ in 0..questions {
        let owner = reader.name()?;
        let asked_type = reader.u16()?;
        reader.skip(2)?;
        let asked = name.strip_suffix('.').unwrap_or(name);
        if questions != 1 || asked_type != qtype.code() || !owner.eq_ignore_ascii_case(asked) {
            return Err(WireError::Malformed("question does not match the query"));
        }
    }

    match (flags & 0x000F) as u8 {
        0 => {}
        3 => return Ok(Reply::NxDomain),
        rcode => return Ok(Reply::Error(rcode)),
    }

    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for _ in 0..answers {
        // The parser does not compare owners, but the name must still parse.
        reader.name()?;
        let kind = reader.u16()?;
        let class = reader.u16()?;
        reader.skip(4)?;
        let length = usize::from(reader.u16()?);
        let data = reader.bytes(length)?;
        if class != CLASS_IN || kind != qtype.code() {
            continue;
        }
        match (qtype, data.len()) {
            (QType::A, 4) => v4.push(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
            (QType::Aaaa, 16) => {
                let mut octets = [0; 16];
                octets.copy_from_slice(data);
                v6.push(Ipv6Addr::from(octets));
            }
            _ => return Err(WireError::Malformed("address of a wrong length")),
        }
    }
    Ok(Reply::Addresses { v4, v6 })
}

/// A bounds-checked cursor over a message.
struct Reader<'a> {
    message: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Reads `count` bytes.
    fn bytes(&mut self, count: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .pos
            .checked_add(count)
            .filter(|&end| end <= self.message.len())
            .ok_or(WireError::Malformed("message cut short"))?;
        let bytes = &self.message[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    /// Skips `count` bytes.
    fn skip(&mut self, count: usize) -> Result<(), WireError> {
        self.bytes(count).map(drop)
    }

    /// Reads a big-endian `u16`.
    fn u16(&mut self) -> Result<u16, WireError> {
        let bytes = self.bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Reads a name, following compression pointers, as dotted text
    /// without the root dot. The cursor moves past the name as it appears
    /// here, not past where its pointers lead.
    fn name(&mut self) -> Result<String, WireError> {
        let (name, next) = read_name(self.message, self.pos)?;
        self.pos = next;
        Ok(name)
    }
}

/// Reads the name at `start` and returns it with the offset after it.
///
/// A pointer must point strictly before itself, and the function follows at
/// most [`MAX_POINTERS`] pointers. Together with the 255-octet limit, these
/// rules end every loop, including a loop through labels.
///
/// # Errors
///
/// Returns [`WireError::Malformed`] if the name is cut short, is too long,
/// loops, or has an unknown label type.
fn read_name(message: &[u8], start: usize) -> Result<(String, usize), WireError> {
    let cut = WireError::Malformed("message cut short");
    let mut name = String::new();
    // Wire length so far: the length octets and the labels.
    let mut length = 0;
    let mut pos = start;
    let mut next = None;
    let mut pointers = 0;
    loop {
        let octet = *message.get(pos).ok_or(cut)?;
        match octet & 0xC0 {
            0x00 if octet == 0 => {
                return Ok((name, next.unwrap_or(pos + 1)));
            }
            0x00 => {
                let size = usize::from(octet);
                let label = message.get(pos + 1..pos + 1 + size).ok_or(cut)?;
                length += 1 + size;
                if length + 1 > MAX_NAME {
                    return Err(WireError::Malformed("name too long"));
                }
                if !name.is_empty() {
                    name.push('.');
                }
                // Names in answers are ASCII in practice. The parser keeps
                // other bytes visible instead of rejecting them.
                name.push_str(&String::from_utf8_lossy(label));
                pos += 1 + size;
            }
            0xC0 => {
                let low = *message.get(pos + 1).ok_or(cut)?;
                let target = usize::from(octet & 0x3F) << 8 | usize::from(low);
                pointers += 1;
                if target >= pos || pointers > MAX_POINTERS {
                    return Err(WireError::Malformed("compression loop"));
                }
                next.get_or_insert(pos + 2);
                pos = target;
            }
            _ => return Err(WireError::Malformed("unknown label type")),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds a reply to `query` by hand: the header with `rcode`, the
    /// question copied, and `answers` as `(owner, type, rdata)`, where an
    /// owner of `None` is a pointer to the question name.
    pub(crate) fn reply(
        query: &[u8],
        rcode: u8,
        answers: &[(Option<&str>, u16, &[u8])],
    ) -> Vec<u8> {
        let mut message = query[..2].to_vec();
        message.extend_from_slice(&(0x8180_u16 | u16::from(rcode)).to_be_bytes());
        message.extend_from_slice(&[0, 1]);
        message.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        message.extend_from_slice(&[0, 0, 0, 0]);
        message.extend_from_slice(&query[HEADER..]);
        for (owner, kind, data) in answers {
            match owner {
                Some(owner) => encode_name(&mut message, owner).unwrap(),
                None => message.extend_from_slice(&[0xC0, HEADER as u8]),
            }
            message.extend_from_slice(&kind.to_be_bytes());
            message.extend_from_slice(&CLASS_IN.to_be_bytes());
            message.extend_from_slice(&300_u32.to_be_bytes());
            message.extend_from_slice(&(data.len() as u16).to_be_bytes());
            message.extend_from_slice(data);
        }
        message
    }

    #[test]
    fn query_layout() {
        let message = query(0xBEEF, "ex.test", QType::Aaaa).unwrap();
        assert_eq!(
            message,
            [
                0xBE, 0xEF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, // header
                2, b'e', b'x', 4, b't', b'e', b's', b't', 0, // name
                0, 28, 0, 1, // AAAA IN
            ]
        );
        assert_eq!(
            query(1, "ex.test.", QType::A).unwrap()[HEADER..21],
            message[HEADER..21]
        );
    }

    #[test]
    fn invalid_names() {
        assert_eq!(query(1, "", QType::A), Err(WireError::InvalidName));
        assert_eq!(query(1, "ex..test", QType::A), Err(WireError::InvalidName));
        let long_label = "a".repeat(64);
        assert_eq!(query(1, &long_label, QType::A), Err(WireError::InvalidName));
        let long_name = vec!["a".repeat(63); 4].join(".");
        assert_eq!(query(1, &long_name, QType::A), Err(WireError::InvalidName));
        let longest = [
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(61),
        ]
        .join(".");
        assert!(query(1, &longest, QType::A).is_ok());
    }

    #[test]
    fn addresses_through_a_cname_chain() {
        let q = query(7, "www.example.test", QType::A).unwrap();
        let message = reply(
            &q,
            0,
            &[
                (None, 5, b"\x03cdn\x07example\x04test\x00"),
                (Some("cdn.example.test"), 1, &[192, 0, 2, 1]),
                (Some("cdn.example.test"), 1, &[192, 0, 2, 2]),
                // The parser ignores a record of another type.
                (Some("cdn.example.test"), 28, &[0; 16]),
            ],
        );
        assert_eq!(
            parse(&message, 7, "www.example.test", QType::A).unwrap(),
            Reply::Addresses {
                v4: vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)],
                v6: vec![],
            }
        );
    }

    #[test]
    fn aaaa_answers() {
        let q = query(9, "ex.test", QType::Aaaa).unwrap();
        let address: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let message = reply(&q, 0, &[(None, 28, &address.octets())]);
        assert_eq!(
            parse(&message, 9, "EX.TEST", QType::Aaaa).unwrap(),
            Reply::Addresses {
                v4: vec![],
                v6: vec![address],
            }
        );
    }

    #[test]
    fn rcodes() {
        let q = query(3, "nx.example.test", QType::A).unwrap();
        assert_eq!(
            parse(&reply(&q, 3, &[]), 3, "nx.example.test", QType::A).unwrap(),
            Reply::NxDomain
        );
        assert_eq!(
            parse(&reply(&q, 2, &[]), 3, "nx.example.test", QType::A).unwrap(),
            Reply::Error(2)
        );
        assert_eq!(rcode_name(2), "SERVFAIL");
        assert_eq!(rcode_name(9), "RCODE 9");
        let empty = parse(&reply(&q, 0, &[]), 3, "nx.example.test", QType::A).unwrap();
        assert_eq!(
            empty,
            Reply::Addresses {
                v4: vec![],
                v6: vec![]
            }
        );
    }

    #[test]
    fn foreign_replies() {
        let q = query(3, "ex.test", QType::A).unwrap();
        let message = reply(&q, 0, &[]);
        assert_eq!(
            parse(&message, 4, "ex.test", QType::A),
            Err(WireError::IdMismatch)
        );
        assert_eq!(
            parse(&message, 3, "ex.example", QType::A),
            Err(WireError::Malformed("question does not match the query"))
        );
        assert_eq!(
            parse(&q, 3, "ex.test", QType::A),
            Err(WireError::Malformed("not a response"))
        );
    }

    #[test]
    fn truncated_replies() {
        let q = query(3, "ex.test", QType::A).unwrap();
        let message = reply(&q, 0, &[(None, 1, &[192, 0, 2, 1])]);
        for end in 0..message.len() {
            assert!(
                parse(&message[..end], 3, "ex.test", QType::A).is_err(),
                "cut at {end}"
            );
        }
        // An address of a wrong length.
        let message = reply(&q, 0, &[(None, 1, &[192, 0, 2])]);
        assert!(parse(&message, 3, "ex.test", QType::A).is_err());
    }

    #[test]
    fn pointers() {
        // "example.test" at 0, and "www" with a pointer to it at 14.
        let message = b"\x07example\x04test\x00\x03www\xC0\x00";
        assert_eq!(
            read_name(message, 14).unwrap(),
            ("www.example.test".into(), 20)
        );
        assert_eq!(read_name(message, 0).unwrap(), ("example.test".into(), 14));
    }

    #[test]
    fn pointer_loops() {
        // A pointer to itself.
        assert_eq!(
            read_name(b"\xC0\x00", 0),
            Err(WireError::Malformed("compression loop"))
        );
        // A pointer forward.
        assert!(read_name(b"\xC0\x02\x00", 0).is_err());
        // A loop through a label: at 2 the label "a", at 4 a pointer back
        // to 2. Each pass points backwards, yet never ends.
        let message = b"\x00\x00\x01a\xC0\x02";
        assert!(read_name(message, 4).is_err());
        // A pointer to a pointer that points forward again.
        let message = b"\x00\x00\xC0\x04\xC0\x02";
        assert!(read_name(message, 4).is_err());
        // Unknown label types: 0x40 and 0x80.
        assert!(read_name(b"\x40", 0).is_err());
        assert!(read_name(b"\x80", 0).is_err());
    }

    #[test]
    fn long_names_through_pointers() {
        // 200 labels "a" chained by pointers backwards exceed 255 octets.
        let mut message = vec![0];
        let mut previous = 0;
        for _ in 0..200 {
            let here = message.len();
            message.extend_from_slice(&[1, b'a', 0xC0 | (previous >> 8) as u8, previous as u8]);
            previous = here;
        }
        assert!(read_name(&message, previous).is_err());
    }

    #[test]
    fn ids_vary() {
        let ids: std::collections::HashSet<u16> = (0..64).map(|_| random_id()).collect();
        assert!(ids.len() > 32);
    }
}

//! A streaming reader of RPSL objects, the format of the APNIC and AFRINIC
//! database dumps.
//!
//! ```text
//! % comment of the dump
//! inetnum:        192.0.2.0 - 192.0.2.255
//! netname:        EXAMPLE-NET
//! descr:          a value that goes on
//!                 on the next line
//! +               and after an empty continuation
//! mnt-by:         EXAMPLE-MNT
//!
//! aut-num:        AS64496
//! ```
//!
//! An object is a run of lines up to an empty line or the end of the input.
//! The class of an object is the name of its first attribute. An attribute
//! line is `name: value`, with the name at the start of the line. A line
//! that starts with a space, a tab, or `+` continues the value of the
//! previous attribute, joined with one space (RFC 2622, section 2). Lines
//! that start with `%` or `#` are comments, and the reader skips them
//! anywhere. The reader also ignores any other line that is not an
//! attribute.
//!
//! The reader lowers attribute names and trims values. It does not strip
//! end-of-line `#` comments, because `#` is ordinary text in values such as
//! names. The code that reads a value handles such comments.
//!
//! [`RpslReader`] takes one line at a time from the
//! [`LineSink`](crate::fetch::lines::LineSink) of its caller and returns
//! each object when it ends. It keeps only the classes and attributes that
//! the caller asked for. The object being read is the whole state, so a
//! dump is never held in memory. The reader never stores what it skips,
//! such as persons, roles, and remarks. The kept text of one object is
//! limited to [`MAX_OBJECT`] bytes, and attributes past the limit are
//! dropped. An object whose class line alone is over the limit is skipped.
//!
//! The RIPE REST API returns the same pairs in JSON.
//! [`RpslObject::from_pairs`] turns them into an object, so the same code
//! reads objects from both sources.

/// The most text kept of one object, in bytes.
///
/// Attributes past this limit are dropped.
pub(crate) const MAX_OBJECT: usize = 64 << 10;

/// One object, reduced to the attributes asked for.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RpslObject {
    /// Names and values, one after the other.
    text: String,
    /// For each attribute, the offsets in `text` where its name starts, its
    /// name ends, and its value starts.
    ///
    /// The value ends where the next name starts.
    attrs: Vec<(u32, u32, u32)>,
}

impl RpslObject {
    /// Creates an object from `(name, value)` pairs.
    ///
    /// The first pair is the class. As with a dump, names are lowered and
    /// values are trimmed. Pairs past [`MAX_OBJECT`] are dropped.
    pub(crate) fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut object = Self::default();
        for (name, value) in pairs {
            if object.text.len() + name.len() + value.len() > MAX_OBJECT {
                break;
            }
            object.push(name, value.trim());
        }
        object
    }

    /// Returns the class: the name of the first attribute.
    pub(crate) fn class(&self) -> Option<&str> {
        self.attrs().next().map(|(name, _)| name)
    }

    /// Returns the attributes in order, the class first.
    pub(crate) fn attrs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.attrs
            .iter()
            .enumerate()
            .map(|(i, &(start, name_end, value_start))| {
                let end = self
                    .attrs
                    .get(i + 1)
                    .map_or(self.text.len(), |next| next.0 as usize);
                (
                    &self.text[start as usize..name_end as usize],
                    &self.text[value_start as usize..end],
                )
            })
    }

    /// Returns the values of the attribute `name`, which must be in lower
    /// case.
    pub(crate) fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.attrs()
            .filter(move |(key, _)| *key == name)
            .map(|(_, value)| value)
    }

    /// Returns `true` if the object has no attribute.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }

    fn clear(&mut self) {
        self.text.clear();
        self.attrs.clear();
    }

    /// Appends an attribute and lowers its name.
    fn push(&mut self, name: &str, value: &str) {
        let start = self.text.len() as u32;
        self.text.push_str(name);
        self.text[start as usize..].make_ascii_lowercase();
        let name_end = self.text.len() as u32;
        self.text.push_str(value);
        self.attrs.push((start, name_end, name_end));
    }

    /// Appends `more` to the value of the last attribute, after one space if
    /// the value is not empty.
    fn extend(&mut self, more: &str) {
        let Some(&(_, _, value_start)) = self.attrs.last() else {
            return;
        };
        if more.is_empty() {
            return;
        }
        if self.text.len() > value_start as usize {
            self.text.push(' ');
        }
        self.text.push_str(more);
    }

    /// Returns the capacity held, in bytes, for the memory tests.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.text.capacity() + self.attrs.capacity() * std::mem::size_of::<(u32, u32, u32)>()
    }
}

/// What the reader does with the lines of the current object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    /// Between objects.
    Between,
    /// In an object of a kept class.
    ///
    /// `keep` is `true` if the reader keeps the current attribute, and with
    /// it the continuation lines of that attribute.
    Keeping { keep: bool },
    /// In an object of another class, up to its end.
    Skipping,
    /// The reader has returned the object and clears it on the next line.
    Done,
}

/// Turns lines into objects of the kept classes, one at a time.
#[derive(Debug)]
pub(crate) struct RpslReader {
    classes: &'static [&'static str],
    attrs: &'static [&'static str],
    object: RpslObject,
    state: State,
    /// The kept text reached [`MAX_OBJECT`].
    full: bool,
}

impl RpslReader {
    /// Creates a reader that keeps the objects whose class is in `classes`.
    ///
    /// Of each object, the reader keeps the class attribute and the
    /// attributes in `attrs`. Both lists hold names in lowercase.
    pub(crate) fn new(classes: &'static [&'static str], attrs: &'static [&'static str]) -> Self {
        Self {
            classes,
            attrs,
            object: RpslObject::default(),
            state: State::Between,
            full: false,
        }
    }

    /// Reads one line without its terminator.
    ///
    /// Returns the object that the line ends, if the reader keeps that
    /// object.
    pub(crate) fn line(&mut self, line: &[u8]) -> Option<&RpslObject> {
        if self.state == State::Done {
            self.object.clear();
            self.full = false;
            self.state = State::Between;
        }
        let Some(&first) = line.first() else {
            return self.end();
        };
        if first == b'%' || first == b'#' {
            return None;
        }
        if first == b' ' || first == b'\t' || first == b'+' {
            if self.state == (State::Keeping { keep: true }) {
                let text = String::from_utf8_lossy(&line[1..]);
                let more = text.trim();
                if self.object.text.len() + more.len() + 1 > MAX_OBJECT {
                    self.full = true;
                    self.state = State::Keeping { keep: false };
                } else {
                    self.object.extend(more);
                }
            }
            return None;
        }
        let (name, value) = split_attr(line)?;
        match self.state {
            State::Between => {
                let name = String::from_utf8_lossy(name).to_ascii_lowercase();
                self.state = State::Skipping;
                if self.classes.contains(&name.as_str()) {
                    let value = String::from_utf8_lossy(value);
                    let value = value.trim();
                    // An object whose class line alone is over the limit is
                    // skipped.
                    if self.object.text.len() + name.len() + value.len() <= MAX_OBJECT {
                        self.object.push(&name, value);
                        self.state = State::Keeping { keep: true };
                    }
                }
            }
            State::Keeping { .. } => {
                let name = String::from_utf8_lossy(name).to_ascii_lowercase();
                let keep = !self.full && self.attrs.contains(&name.as_str());
                if keep {
                    let value = String::from_utf8_lossy(value);
                    let value = value.trim();
                    if self.object.text.len() + name.len() + value.len() > MAX_OBJECT {
                        self.full = true;
                        self.state = State::Keeping { keep: false };
                        return None;
                    }
                    self.object.push(&name, value);
                }
                self.state = State::Keeping { keep };
            }
            State::Skipping | State::Done => {}
        }
        None
    }

    /// Ends the input.
    ///
    /// Returns the last object if the input did not end with an empty line
    /// and the reader keeps that object.
    pub(crate) fn finish(&mut self) -> Option<&RpslObject> {
        if self.state == State::Done {
            self.object.clear();
            self.state = State::Between;
        }
        self.end()
    }

    /// Ends the current object at an empty line or at the end of the input.
    fn end(&mut self) -> Option<&RpslObject> {
        match self.state {
            State::Keeping { .. } => {
                self.state = State::Done;
                Some(&self.object)
            }
            _ => {
                self.state = State::Between;
                None
            }
        }
    }

    /// Returns the capacity held, in bytes, for the memory tests.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.object.held()
    }
}

/// Splits a `name: value` line at its first colon.
///
/// Returns `None` if the line has no colon, or if the name is empty or holds
/// anything other than ASCII letters, digits, `-`, and `_`. The name must
/// therefore start the line.
fn split_attr(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = line.iter().position(|&b| b == b':')?;
    let name = &line[..colon];
    if name.is_empty()
        || !name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
    {
        return None;
    }
    Some((name, &line[colon + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLASSES: &[&str] = &["inetnum", "aut-num"];
    const ATTRS: &[&str] = &["netname", "descr", "mnt-by"];

    fn read(text: &str) -> Vec<Vec<(String, String)>> {
        let mut reader = RpslReader::new(CLASSES, ATTRS);
        let mut out = Vec::new();
        let mut keep = |object: &RpslObject| {
            out.push(
                object
                    .attrs()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
            );
        };
        for line in text.split('\n') {
            if let Some(object) = reader.line(line.as_bytes()) {
                keep(object);
            }
        }
        if let Some(object) = reader.finish() {
            keep(object);
        }
        out
    }

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn objects_attributes_and_continuations() {
        let text = "% header of the dump\n\
            \n\
            INETNUM:   192.0.2.0 - 192.0.2.255\n\
            netname:   EXAMPLE-NET\n\
            descr:     first\n  \tsecond line\n+\n+ third\n\
            # a comment inside\n\
            country:   XD\n\
            mnt-by:    EXAMPLE-MNT\n\
            \n\
            person:    John Doe\n\
            e-mail:    john@example.net\n\
            mnt-by:    PERSON-MNT\n\
            \n\
            aut-num:   AS64496\n\
            mnt-by:EXAMPLE-MNT";
        assert_eq!(
            read(text),
            [
                pairs(&[
                    ("inetnum", "192.0.2.0 - 192.0.2.255"),
                    ("netname", "EXAMPLE-NET"),
                    ("descr", "first second line third"),
                    ("mnt-by", "EXAMPLE-MNT"),
                ]),
                pairs(&[("aut-num", "AS64496"), ("mnt-by", "EXAMPLE-MNT")]),
            ]
        );
    }

    #[test]
    fn junk_and_dropped_attributes() {
        // A line that is not an attribute is ignored. A continuation of a
        // dropped attribute is dropped with it. Several empty lines are one
        // separator.
        let text = "inetnum: 192.0.2.0 - 192.0.2.255\nremarks: x\n continued\n\
            not an attribute\nbad name: y\nnetname: N\n\n\n\naut-num: AS64497\n\n";
        assert_eq!(
            read(text),
            [
                pairs(&[("inetnum", "192.0.2.0 - 192.0.2.255"), ("netname", "N")]),
                pairs(&[("aut-num", "AS64497")]),
            ]
        );
    }

    #[test]
    fn an_object_is_capped() {
        let mut text = String::from("inetnum: 192.0.2.0 - 192.0.2.255\n");
        let long = "x".repeat(1000);
        for _ in 0..100 {
            text.push_str(&format!("descr: {long}\n"));
        }
        text.push_str("netname: LAST\n");
        let objects = read(&text);
        assert_eq!(objects.len(), 1);
        let kept: usize = objects[0].iter().map(|(k, v)| k.len() + v.len()).sum();
        assert!(kept <= MAX_OBJECT);
        assert!(objects[0].iter().all(|(k, _)| k != "netname"));

        // A class line over the limit drops its object.
        let text = format!(
            "inetnum: {}\nnetname: N\n\naut-num: AS64497\n",
            "x".repeat(MAX_OBJECT)
        );
        assert_eq!(read(&text), [pairs(&[("aut-num", "AS64497")])]);
    }

    #[test]
    fn pairs_from_json() {
        let object = RpslObject::from_pairs([("Aut-Num", " AS64496 "), ("mnt-by", "A-MNT")]);
        assert_eq!(object.class(), Some("aut-num"));
        assert_eq!(object.values("mnt-by").collect::<Vec<_>>(), ["A-MNT"]);
        assert!(!object.is_empty());
        assert!(RpslObject::from_pairs([]).class().is_none());
    }
}

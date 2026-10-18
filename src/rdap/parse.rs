//! Parses RDAP JSON into the model: networks, AS, organizations, contacts
//! from vCards, links up the chain, and notices about truncated responses.
//!
//! The responses are RFC 9083 objects. netf reads only the fields it shows or
//! searches. The five registries agree on the meaning of the roles in
//! `entities`:
//!
//! - A `registrant` of kind `individual` is a maintainer (`*.mnt`). RIPE
//!   lists its maintainers this way. Any other `registrant` is the holder
//!   organization (`*.org`). If there are several, netf takes the first.
//! - `administrative`, `technical`, and `abuse` are contacts. One handle can
//!   hold several roles and is still one [`Contact`]. LACNIC gives one
//!   handle all three.
//! - The contacts of the holder are contacts of the record too, because
//!   ARIN keeps them inside the organization. Entities inside a contact are
//!   not contacts of the record. RIPE nests the persons of a role object
//!   inside the role.
//!
//! RIPE hides the e-mail of persons in these responses. Such a contact gets
//! [`Contact::emails_hidden`], so that `--ripe-emails` can fetch the
//! e-mail. Role objects and the abuse contact keep their e-mail.
//!
//! Values are taken as they come. A field of the wrong type counts as
//! missing. Only a network without addresses, an AS without a number, or
//! an entity without a handle is an invalid response.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    addr::{Addr, Family, Prefix, Range},
    model::{AsRecord, Asn, Contact, EntityKind, NetRecord, Org, OrgRef, RecordOrigin, Rir, Role},
};

/// An RDAP entity looked up by handle.
///
/// The entity is a person, a role, or an organization, with the resources
/// that the registry lists for the entity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Entity {
    /// The registry.
    pub(crate) rir: Rir,
    /// The handle.
    pub(crate) handle: String,
    /// The vCard kind.
    pub(crate) kind: EntityKind,
    /// The name (`fn`).
    pub(crate) name: Option<String>,
    /// The postal address, on one line.
    pub(crate) address: Option<String>,
    /// The phone number.
    pub(crate) phone: Option<String>,
    /// The e-mail addresses.
    pub(crate) email: Vec<String>,
    /// The networks listed with the entity (`networks`).
    pub(crate) networks: Vec<NetRecord>,
    /// The AS listed with the entity (`autnums`).
    pub(crate) autnums: Vec<AsRecord>,
    /// The registry's message if it truncated the lists.
    pub(crate) truncated: Option<String>,
}

impl Entity {
    /// Returns the entity as an organization with only the resources it
    /// holds itself.
    ///
    /// A listed record whose holder is another organization is dropped,
    /// because the entity is only the sponsor of such a record. A record
    /// without a holder is kept.
    pub(crate) fn to_org(&self) -> Org {
        let own = |org: &Option<OrgRef>| {
            org.as_ref()
                .is_none_or(|org| org.handle.eq_ignore_ascii_case(&self.handle))
        };
        Org {
            rir: self.rir,
            handle: self.handle.clone(),
            name: self.name.clone(),
            networks: self
                .networks
                .iter()
                .filter(|net| own(&net.org))
                .cloned()
                .collect(),
            autnums: self
                .autnums
                .iter()
                .filter(|record| own(&record.org))
                .cloned()
                .collect(),
            truncated: self.truncated.clone(),
        }
    }
}

/// Parses an `ip network` response of `rir`.
///
/// # Errors
///
/// Returns an error if the response has no addresses.
pub(crate) fn network(value: &Value, rir: Rir) -> Result<NetRecord, String> {
    let range = range(value).ok_or("a network without addresses")?;
    let roles = Roles::of(value, rir);
    Ok(NetRecord {
        rir,
        range,
        handle: text(value, "handle").unwrap_or_else(|| range.to_string()),
        name: text(value, "name"),
        country: text(value, "country").and_then(|cc| cc.parse().ok()),
        org: roles.org,
        mnt: roles.mnt,
        contacts: roles.contacts,
        parent_link: link(value, "up"),
        origin: RecordOrigin::Rdap,
    })
}

/// Parses an `autnum` response of `rir`.
///
/// `asn` is the number asked about. The parser uses `asn` if the response
/// gives no number. A block of AS keeps its last number from `endAutnum`.
///
/// # Errors
///
/// Returns an error if neither the response nor `asn` gives a number.
pub(crate) fn autnum(value: &Value, rir: Rir, asn: Option<Asn>) -> Result<AsRecord, String> {
    let asn = number(value).or(asn).ok_or("an AS without a number")?;
    let last = value
        .get("endAutnum")
        .and_then(Value::as_u64)
        .and_then(|n| Asn::try_from(n).ok())
        .filter(|&last| last > asn);
    let roles = Roles::of(value, rir);
    Ok(AsRecord {
        rir,
        asn,
        last,
        name: text(value, "name"),
        org: roles.org,
        mnt: roles.mnt,
        contacts: roles.contacts,
    })
}

/// Parses an `entity` response of `rir`, with the networks and AS it lists.
///
/// List items that do not parse are skipped.
///
/// # Errors
///
/// Returns an error if the response has no handle.
pub(crate) fn entity(value: &Value, rir: Rir) -> Result<Entity, String> {
    let handle = text(value, "handle").ok_or("an entity without a handle")?;
    let card = VCard::of(value);
    let list = |name| {
        value
            .get(name)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
    };
    Ok(Entity {
        rir,
        handle,
        kind: card.kind,
        name: card.name,
        address: card.address,
        phone: card.phone,
        email: card.email,
        networks: list("networks")
            .filter_map(|net| network(net, rir).ok())
            .collect(),
        autnums: list("autnums")
            .filter_map(|record| autnum(record, rir, None).ok())
            .collect(),
        truncated: truncated(value),
    })
}

/// Returns the organizations of an `entities` search response.
///
/// The results are in `entitySearchResults` (RFC 9083, section 8). The
/// function returns the handle and the name of each entity of kind `org`
/// that has both. Persons, roles, and entities of no kind are skipped.
/// Nothing else of an entity is read.
pub(crate) fn search_orgs(value: &Value) -> Vec<(String, String)> {
    value
        .get("entitySearchResults")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entity| {
            let card = VCard::of(entity);
            if card.kind != EntityKind::Org {
                return None;
            }
            Some((text(entity, "handle")?, one_line(&card.name?)))
        })
        .collect()
}

/// Returns the registry's message if it says the response is truncated.
///
/// Such a message is a notice of type `result set truncated …` (RFC 9083,
/// section 10.2.1). It can also be a notice whose description, or else its
/// title, speaks of limited or truncated results, as RIPE's does. The
/// message is returned on one line.
pub(crate) fn truncated(value: &Value) -> Option<String> {
    let notices = value.get("notices").and_then(Value::as_array)?;
    for notice in notices {
        if let Some(kind) = text(notice, "type")
            && kind
                .to_ascii_lowercase()
                .starts_with("result set truncated")
        {
            return Some(one_line(&kind));
        }
        // The description is the registry's message. The title only
        // names it ("Truncated").
        let lines = notice
            .get("description")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .chain(text(notice, "title"));
        for line in lines {
            let lower = line.to_ascii_lowercase();
            if lower.contains("limited search results") || lower.contains("truncated") {
                return Some(one_line(&line));
            }
        }
    }
    None
}

/// Returns the `errorCode` of an RDAP error response.
pub(crate) fn error_code(value: &Value) -> Option<u64> {
    value.get("errorCode").and_then(Value::as_u64)
}

/// The holder, maintainers, and contacts that the `entities` of a record
/// name.
#[derive(Default)]
struct Roles {
    org: Option<OrgRef>,
    mnt: Vec<String>,
    contacts: Vec<Contact>,
}

impl Roles {
    fn of(value: &Value, rir: Rir) -> Self {
        let mut roles = Self::default();
        for entity in entities(value) {
            roles.take(entity, rir, true);
        }
        roles
    }

    /// Takes one entity of the record.
    ///
    /// `top` is false for the entities inside the holder. Their registrants
    /// are not the record's.
    fn take(&mut self, entity: &Value, rir: Rir, top: bool) {
        let names: Vec<Role> = entity
            .get("roles")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter_map(|role| role.parse().ok())
            .collect();
        let card = VCard::of(entity);
        let handle = text(entity, "handle");
        if top && names.contains(&Role::Registrant) {
            if card.kind == EntityKind::Individual {
                if let Some(handle) = &handle
                    && !self.mnt.contains(handle)
                {
                    self.mnt.push(handle.clone());
                }
            } else {
                if self.org.is_none()
                    && let Some(handle) = &handle
                {
                    self.org = Some(OrgRef {
                        handle: handle.clone(),
                        name: card.name.clone(),
                    });
                }
                // ARIN keeps the contacts inside the holder.
                for inner in entities(entity) {
                    self.take(inner, rir, false);
                }
            }
        }
        let contact_roles: Vec<Role> = names
            .into_iter()
            .filter(|role| *role != Role::Registrant)
            .collect();
        let Some(handle) = handle else {
            return;
        };
        if contact_roles.is_empty() {
            return;
        }
        let emails_hidden =
            rir == Rir::Ripencc && card.email.is_empty() && card.kind != EntityKind::Org;
        let contact = Contact {
            handle,
            roles: contact_roles,
            kind: card.kind,
            name: card.name,
            address: card.address,
            phone: card.phone,
            email: card.email,
            rir,
            emails_hidden,
        };
        match self
            .contacts
            .iter_mut()
            .find(|known| known.handle == contact.handle)
        {
            Some(known) => merge(known, contact),
            None => self.contacts.push(contact),
        }
    }
}

/// Adds what `other` knows to `known`.
///
/// `other` is the same handle seen again.
fn merge(known: &mut Contact, other: Contact) {
    for role in other.roles {
        if !known.roles.contains(&role) {
            known.roles.push(role);
        }
    }
    if known.kind == EntityKind::Unknown {
        known.kind = other.kind;
    }
    known.name = known.name.take().or(other.name);
    known.address = known.address.take().or(other.address);
    known.phone = known.phone.take().or(other.phone);
    for email in other.email {
        if !known.email.contains(&email) {
            known.email.push(email);
        }
    }
    known.emails_hidden = known.emails_hidden && known.email.is_empty();
}

/// What netf reads from a vCard (RFC 7095).
#[derive(Debug, PartialEq)]
struct VCard {
    kind: EntityKind,
    name: Option<String>,
    address: Option<String>,
    phone: Option<String>,
    email: Vec<String>,
}

impl VCard {
    fn of(entity: &Value) -> Self {
        let mut card = Self {
            kind: EntityKind::Unknown,
            name: None,
            address: None,
            phone: None,
            email: Vec::new(),
        };
        let properties = entity
            .get("vcardArray")
            .and_then(Value::as_array)
            .and_then(|array| array.get(1))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_array);
        for property in properties {
            let (Some(name), Some(params), Some(value)) = (
                property.first().and_then(Value::as_str),
                property.get(1),
                property.get(3),
            ) else {
                continue;
            };
            match name.to_ascii_lowercase().as_str() {
                "fn" => card.name = card.name.take().or_else(|| nonempty(value)),
                "kind" => {
                    card.kind = match value.as_str().map(str::to_ascii_lowercase).as_deref() {
                        Some("org") => EntityKind::Org,
                        Some("individual") => EntityKind::Individual,
                        Some("group") => EntityKind::Group,
                        _ => EntityKind::Unknown,
                    }
                }
                "adr" => card.address = card.address.take().or_else(|| address(params, value)),
                "tel" => {
                    card.phone = card.phone.take().or_else(|| {
                        nonempty(value).map(|tel| {
                            tel.strip_prefix("tel:")
                                .map_or_else(|| tel.clone(), str::to_owned)
                        })
                    })
                }
                "email" => {
                    if let Some(email) = nonempty(value)
                        && !card.email.contains(&email)
                    {
                        card.email.push(email);
                    }
                }
                _ => {}
            }
        }
        card
    }
}

/// Returns an `adr` on one line, from its `label` or else from its
/// components.
fn address(params: &Value, value: &Value) -> Option<String> {
    let join = |parts: Vec<String>| {
        let parts: Vec<String> = parts
            .iter()
            .flat_map(|part| part.lines())
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect();
        (!parts.is_empty()).then(|| parts.join(", "))
    };
    if let Some(label) = params.get("label") {
        let lines = match label {
            Value::String(text) => vec![text.clone()],
            Value::Array(items) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            _ => Vec::new(),
        };
        if let Some(text) = join(lines) {
            return Some(text);
        }
    }
    let mut parts = Vec::new();
    for component in value.as_array().into_iter().flatten() {
        match component {
            Value::String(text) => parts.push(text.clone()),
            Value::Array(items) => {
                parts.extend(items.iter().filter_map(Value::as_str).map(str::to_owned))
            }
            _ => {}
        }
    }
    join(parts)
}

/// Returns the `entities` of an object.
fn entities(value: &Value) -> impl Iterator<Item = &Value> {
    value
        .get("entities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

/// Returns the string member `name`, trimmed.
///
/// Returns `None` if the member is missing, not a string, or empty.
fn text(value: &Value, name: &str) -> Option<String> {
    value.get(name).and_then(nonempty)
}

/// Returns a string value, trimmed.
///
/// Returns `None` if the value is not a string or is empty.
fn nonempty(value: &Value) -> Option<String> {
    let text = value.as_str()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// Collapses whitespace and line breaks into single spaces.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Returns the `href` of the first link with relation `rel`.
fn link(value: &Value, rel: &str) -> Option<String> {
    value
        .get("links")
        .and_then(Value::as_array)?
        .iter()
        .find(|link| link.get("rel").and_then(Value::as_str) == Some(rel))
        .and_then(|link| text(link, "href"))
}

/// Returns the addresses of a network.
///
/// They come from `startAddress` and `endAddress`, or else from the span of
/// its `cidr0_cidrs`.
fn range(value: &Value) -> Option<Range> {
    let start = text(value, "startAddress").and_then(|a| a.parse::<Addr>().ok());
    let end = text(value, "endAddress").and_then(|a| a.parse::<Addr>().ok());
    if let (Some(start), Some(end)) = (start, end)
        && start.family() == end.family()
        && let Some(range) = Range::new(start.family(), start.bits(), end.bits())
    {
        return Some(range);
    }
    let prefixes = value
        .get("cidr0_cidrs")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|cidr| {
            let addr = text(cidr, "v4prefix").or_else(|| text(cidr, "v6prefix"))?;
            let len = u8::try_from(cidr.get("length")?.as_u64()?).ok()?;
            Prefix::new(addr.parse().ok()?, len).ok()
        });
    let mut span: Option<(Family, u128, u128)> = None;
    for prefix in prefixes {
        span = match span {
            None => Some((prefix.family(), prefix.first(), prefix.last())),
            Some((family, first, last)) if family == prefix.family() => {
                Some((family, first.min(prefix.first()), last.max(prefix.last())))
            }
            other => other,
        };
    }
    let (family, first, last) = span?;
    Range::new(family, first, last)
}

/// Returns the number of an AS response.
///
/// The number comes from `startAutnum` if the response has it, and from
/// the handle otherwise, with or without the `AS` prefix. LACNIC lists AS by handle only, like `AS64496`.
fn number(value: &Value) -> Option<Asn> {
    if let Some(n) = value.get("startAutnum").and_then(Value::as_u64) {
        return Asn::try_from(n).ok();
    }
    let handle = text(value, "handle")?;
    let digits = handle
        .strip_prefix("AS")
        .or_else(|| handle.strip_prefix("as"))
        .unwrap_or(&handle);
    digits.parse().ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::json;

    use super::*;

    /// Builds a vCard with `fn`, `kind`, and the `more` properties.
    pub(crate) fn vcard(name: &str, kind: &str, more: &[Value]) -> Value {
        let mut properties = vec![
            json!(["version", {}, "text", "4.0"]),
            json!(["fn", {}, "text", name]),
            json!(["kind", {}, "text", kind]),
        ];
        properties.extend(more.iter().cloned());
        json!(["vcard", properties])
    }

    fn email(address: &str) -> Value {
        json!(["email", {}, "text", address])
    }

    /// Returns a RIPE network with a maintainer, the holder, a role with
    /// e-mail, a person without e-mail, the abuse role, and a person nested
    /// in the role.
    pub(crate) fn ripe_network() -> Value {
        json!({
            "objectClassName": "ip network",
            "handle": "192.0.2.0 - 192.0.2.255",
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
            "ipVersion": "v4",
            "name": "EXAMPLE-NET",
            "country": "xd",
            "parentHandle": "198.18.0.0 - 198.18.255.255",
            "links": [
                {"rel": "self", "href": "https://rdap.db.ripe.test/ip/192.0.2.0/24"},
                {"rel": "up", "href": "https://rdap.db.ripe.test/ip/198.18.0.0/16"}
            ],
            "entities": [
                {"handle": "EXAMPLE-MNT", "roles": ["registrant"],
                 "vcardArray": vcard("EXAMPLE-MNT", "individual", &[])},
                {"handle": "ORG-EX1-TEST", "roles": ["registrant"],
                 "vcardArray": vcard("Example Org", "org", &[])},
                {"handle": "EXR1-TEST", "roles": ["administrative", "technical"],
                 "vcardArray": vcard("Example Role", "group", &[email("noc@example.net")]),
                 "entities": [
                    {"handle": "JD1-TEST", "roles": ["technical"],
                     "vcardArray": vcard("Jane Doe", "individual", &[])}
                 ]},
                {"handle": "JR1-TEST", "roles": ["technical"],
                 "vcardArray": vcard("John Roe", "individual", &[
                     json!(["adr", {"label": "1 Example Street\nExample City\nXD"}, "text",
                            ["", "", "", "", "", "", ""]]),
                     json!(["tel", {"type": "voice"}, "uri", "tel:+1-555-0100"])
                 ])},
                {"handle": "EXAB1-TEST", "roles": ["abuse"],
                 "vcardArray": vcard("Abuse", "group", &[email("abuse@example.net")])}
            ],
            "notices": [{"title": "Terms and Conditions", "description": ["Fictional."]}]
        })
    }

    #[test]
    fn ripe_network_roles_and_hidden_emails() {
        let net = network(&ripe_network(), Rir::Ripencc).unwrap();
        assert_eq!(net.range.to_string(), "192.0.2.0/24");
        assert_eq!(net.handle, "192.0.2.0 - 192.0.2.255");
        assert_eq!(net.name.as_deref(), Some("EXAMPLE-NET"));
        assert_eq!(net.country.map(|cc| cc.to_string()).as_deref(), Some("XD"));
        assert_eq!(net.mnt, ["EXAMPLE-MNT"]);
        assert_eq!(
            net.org,
            Some(OrgRef {
                handle: "ORG-EX1-TEST".into(),
                name: Some("Example Org".into())
            })
        );
        assert_eq!(
            net.parent_link.as_deref(),
            Some("https://rdap.db.ripe.test/ip/198.18.0.0/16")
        );
        let handles: Vec<_> = net.contacts.iter().map(|c| c.handle.as_str()).collect();
        // The person inside the role is not a contact of the network.
        assert_eq!(handles, ["EXR1-TEST", "JR1-TEST", "EXAB1-TEST"]);
        let role = &net.contacts[0];
        assert_eq!(role.roles, [Role::Administrative, Role::Technical]);
        assert_eq!(role.email, ["noc@example.net"]);
        assert!(!role.emails_hidden);
        let person = &net.contacts[1];
        assert_eq!(person.kind, EntityKind::Individual);
        assert_eq!(
            person.address.as_deref(),
            Some("1 Example Street, Example City, XD")
        );
        assert_eq!(person.phone.as_deref(), Some("+1-555-0100"));
        assert!(person.email.is_empty());
        assert!(person.emails_hidden);
        assert_eq!(net.contacts[2].email, ["abuse@example.net"]);
        assert_eq!(net.origin, RecordOrigin::Rdap);
        assert_eq!(truncated(&ripe_network()), None);
    }

    #[test]
    fn arin_contacts_inside_the_holder() {
        let value = json!({
            "objectClassName": "ip network",
            "handle": "NET-198-51-100-0-1",
            "startAddress": "198.51.100.0",
            "endAddress": "198.51.100.255",
            "name": "EXAMPLE-ARIN",
            "cidr0_cidrs": [{"v4prefix": "198.51.100.0", "length": 24}],
            "links": [{"rel": "up", "href": "https://rdap.arin.test/registry/ip/198.18.0.0/16"}],
            "entities": [
                {"handle": "EXAMP-1", "roles": ["registrant"],
                 "vcardArray": vcard("Example Holdings", "org", &[
                     json!(["adr", {}, "text",
                            ["", "", ["100 Example Ave", "Suite 1"], "Exampleville", "XX", "00000", "XE"]])
                 ]),
                 "entities": [
                    {"handle": "ABUSE1-ARIN", "roles": ["abuse"],
                     "vcardArray": vcard("Abuse Desk", "group", &[email("abuse@example.net")])},
                    {"handle": "NOC1-ARIN", "roles": ["technical", "administrative"],
                     "vcardArray": vcard("NOC", "group", &[email("noc@example.net")])}
                 ]},
                {"handle": "NOC1-ARIN", "roles": ["technical"],
                 "vcardArray": vcard("NOC", "group", &[email("noc2@example.net")])}
            ]
        });
        let net = network(&value, Rir::Arin).unwrap();
        assert_eq!(net.org.as_ref().unwrap().handle, "EXAMP-1");
        assert!(net.mnt.is_empty());
        let handles: Vec<_> = net.contacts.iter().map(|c| c.handle.as_str()).collect();
        assert_eq!(handles, ["ABUSE1-ARIN", "NOC1-ARIN"]);
        let noc = &net.contacts[1];
        assert_eq!(noc.roles, [Role::Technical, Role::Administrative]);
        assert_eq!(noc.email, ["noc@example.net", "noc2@example.net"]);
        assert!(!noc.emails_hidden);
        // The holder's address is built from its components.
        let holder = VCard::of(&value["entities"][0]);
        assert_eq!(
            holder.address.as_deref(),
            Some("100 Example Ave, Suite 1, Exampleville, XX, 00000, XE")
        );
    }

    #[test]
    fn apnic_v6_from_cidr0_and_truncation() {
        let value = json!({
            "objectClassName": "ip network",
            "handle": "2001:DB8::/32",
            "cidr0_cidrs": [
                {"v6prefix": "2001:db8::", "length": 33},
                {"v6prefix": "2001:db8:8000::", "length": 33}
            ],
            "country": "XG",
            "entities": [
                {"handle": "IRT-EXAMPLE-AP", "roles": ["abuse"],
                 "vcardArray": vcard("IRT-EXAMPLE-AP", "group", &[email("abuse@example.net")])},
                {"handle": "MAINT-EXAMPLE-AP", "roles": ["registrant"],
                 "vcardArray": vcard("MAINT-EXAMPLE-AP", "individual", &[])}
            ],
            "notices": [{"title": "Result set truncated",
                          "type": "result set truncated due to unexplainable reasons",
                          "description": ["Results limited."]}]
        });
        let net = network(&value, Rir::Apnic).unwrap();
        assert_eq!(net.range.to_string(), "2001:db8::/32");
        assert_eq!(net.mnt, ["MAINT-EXAMPLE-AP"]);
        assert_eq!(net.org, None);
        assert_eq!(net.contacts[0].roles, [Role::Abuse]);
        assert!(!net.contacts[0].emails_hidden);
        assert_eq!(
            truncated(&value).as_deref(),
            Some("result set truncated due to unexplainable reasons")
        );
        let ripe = json!({"notices": [{"title": "Search results",
            "description": ["limited search results\n to 100 maximum"]}]});
        assert_eq!(
            truncated(&ripe).as_deref(),
            Some("limited search results to 100 maximum")
        );
    }

    #[test]
    fn lacnic_one_handle_in_three_roles_and_autnums_by_handle() {
        let value = json!({
            "objectClassName": "autnum",
            "handle": "64506",
            "startAutnum": 64506,
            "endAutnum": 64506,
            "name": "EXAMPLE-LACNIC",
            "entities": [
                {"handle": "EXL", "roles": ["registrant"],
                 "vcardArray": vcard("Example Ltda", "org", &[])},
                {"handle": "EXC", "roles": ["administrative", "technical", "abuse"],
                 "vcardArray": vcard("Example Contact", "individual", &[email("contact@example.net")])}
            ]
        });
        let record = autnum(&value, Rir::Lacnic, Some(64506)).unwrap();
        assert_eq!(record.asn, 64506);
        assert_eq!(record.name.as_deref(), Some("EXAMPLE-LACNIC"));
        assert_eq!(record.org.as_ref().unwrap().handle, "EXL");
        assert_eq!(record.contacts.len(), 1);
        assert_eq!(
            record.contacts[0].roles,
            [Role::Administrative, Role::Technical, Role::Abuse]
        );
        let org = json!({
            "objectClassName": "entity",
            "handle": "EXL",
            "vcardArray": vcard("Example Ltda", "org", &[]),
            "autnums": [{"objectClassName": "autnum", "handle": "AS64507"}],
            "networks": [{"objectClassName": "ip network", "handle": "203.0.113.0/24",
                          "startAddress": "203.0.113.0", "endAddress": "203.0.113.255"}]
        });
        let entity = entity(&org, Rir::Lacnic).unwrap();
        assert_eq!(entity.kind, EntityKind::Org);
        assert_eq!(entity.autnums[0].asn, 64507);
        assert_eq!(entity.networks[0].range.to_string(), "203.0.113.0/24");
        let org = entity.to_org();
        assert_eq!((org.networks.len(), org.autnums.len()), (1, 1));
    }

    #[test]
    fn afrinic_autnum_and_an_org_with_a_sponsored_resource() {
        let value = json!({
            "objectClassName": "autnum",
            "handle": "AS64508",
            "name": "EXAMPLE-AFRINIC",
            "entities": [
                {"handle": "ORG-EXA1-AFRINIC", "roles": ["registrant"],
                 "vcardArray": vcard("Example Africa", "org", &[])},
                {"handle": "EXA1-AFRINIC", "roles": ["technical"],
                 "vcardArray": vcard("Example Tech", "individual", &[email("tech@example.net")])}
            ]
        });
        let record = autnum(&value, Rir::Afrinic, None).unwrap();
        assert_eq!(record.asn, 64508);
        assert_eq!(record.contacts[0].email, ["tech@example.net"]);
        let org = json!({
            "handle": "ORG-EXA1-AFRINIC",
            "vcardArray": vcard("Example Africa", "org", &[email("info@example.net")]),
            "networks": [
                network_json("198.18.0.0", "198.18.0.255", "ORG-EXA1-AFRINIC"),
                network_json("198.18.1.0", "198.18.1.255", "ORG-OTHER-AFRINIC")
            ],
            "autnums": [{"startAutnum": 64509, "entities": [
                {"handle": "ORG-OTHER-AFRINIC", "roles": ["registrant"],
                 "vcardArray": vcard("Other", "org", &[])}]}]
        });
        let entity = entity(&org, Rir::Afrinic).unwrap();
        assert_eq!(entity.email, ["info@example.net"]);
        assert_eq!(entity.networks.len(), 2);
        let org = entity.to_org();
        assert_eq!(org.name.as_deref(), Some("Example Africa"));
        assert_eq!(org.networks.len(), 1);
        assert_eq!(org.networks[0].range.to_string(), "198.18.0.0/24");
        assert!(org.autnums.is_empty());
    }

    #[test]
    fn a_block_of_as_keeps_its_last_number() {
        let block = autnum(
            &json!({"startAutnum": 64499, "endAutnum": 64502}),
            Rir::Arin,
            None,
        )
        .unwrap();
        assert_eq!(block.numbers(), (64499, 64502));
        let single = autnum(
            &json!({"startAutnum": 64499, "endAutnum": 64499}),
            Rir::Arin,
            None,
        )
        .unwrap();
        assert_eq!((single.last, single.numbers()), (None, (64499, 64499)));
        let backwards = json!({"startAutnum": 64502, "endAutnum": 64499});
        assert_eq!(autnum(&backwards, Rir::Arin, None).unwrap().last, None);
    }

    fn network_json(start: &str, end: &str, holder: &str) -> Value {
        json!({"startAddress": start, "endAddress": end, "entities": [
            {"handle": holder, "roles": ["registrant"], "vcardArray": vcard(holder, "org", &[])}
        ]})
    }

    #[test]
    fn invalid_answers() {
        assert_eq!(
            network(&json!({"handle": "X"}), Rir::Arin).unwrap_err(),
            "a network without addresses"
        );
        let mixed = json!({"startAddress": "192.0.2.0", "endAddress": "2001:db8::"});
        assert!(network(&mixed, Rir::Arin).is_err());
        assert_eq!(
            autnum(&json!({"name": "X"}), Rir::Arin, None).unwrap_err(),
            "an AS without a number"
        );
        assert!(entity(&json!({}), Rir::Arin).is_err());
        assert_eq!(error_code(&json!({"errorCode": 404})), Some(404));
        // A single address without a handle gets the range as its handle.
        let host = network(
            &json!({"startAddress": "192.0.2.1", "endAddress": "192.0.2.1", "vcardArray": 5}),
            Rir::Arin,
        )
        .unwrap();
        assert_eq!(host.handle, "192.0.2.1/32");
    }
}

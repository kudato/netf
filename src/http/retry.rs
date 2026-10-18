//! The retry policy: `Retry-After` on a 429, pauses on a 5xx or a network
//! error, and when to give up.
//!
//! - **429**: the egress waits for the host as long as `Retry-After` says.
//!   The value is delay-seconds or an IMF-fixdate, as RFC 9110, section
//!   10.2.3 defines it. Without a readable header, the wait is 60 s. The
//!   request gives up on a pause over an hour, or on its sixth 429 in a
//!   row.
//! - **5xx and network errors**: two more attempts, after 1 s and 4 s. A
//!   network error is a refused or reset connection, a timeout, or a body
//!   cut short. A 501 is not retried, because the server never does what
//!   the request asks.
//!
//! This module holds only the arithmetic, and the transport applies it.

use std::time::{Duration, SystemTime};

/// The pause after a 429 without a usable `Retry-After`.
pub(crate) const DEFAULT_RATE_LIMIT_WAIT: Duration = Duration::from_secs(60);

/// The longest pause that netf waits out. A longer pause is an error.
pub(crate) const MAX_RATE_LIMIT_WAIT: Duration = Duration::from_secs(3600);

/// How many 429 responses in a row one request accepts. The next 429 is an
/// error.
pub(crate) const MAX_RATE_LIMITED: u32 = 5;

/// The pauses before the second and the third attempt after a 5xx or a
/// network error.
pub(crate) const RETRY_PAUSES: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(4)];

/// Returns how long to wait at `now` after a 429 with this `Retry-After`
/// value.
///
/// A date in the past means "now". A number too large for the clock becomes
/// [`Duration::MAX`], so that the caller gives up instead of retrying at
/// once.
pub(crate) fn retry_after(value: Option<&str>, now: SystemTime) -> Duration {
    let Some(value) = value.map(str::trim) else {
        return DEFAULT_RATE_LIMIT_WAIT;
    };
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        return value.parse().map_or(Duration::MAX, Duration::from_secs);
    }
    match imf_fixdate(value) {
        Some(date) => date.duration_since(now).unwrap_or(Duration::ZERO),
        None => DEFAULT_RATE_LIMIT_WAIT,
    }
}

/// Parses an IMF-fixdate such as `Sun, 06 Nov 1994 08:49:37 GMT`.
///
/// RFC 9110, section 5.6.7 defines the format, and a server must send its
/// dates in it. The function rejects the obsolete RFC 850 and asctime
/// forms, so a `Retry-After` in them gets the default wait.
pub(crate) fn imf_fixdate(text: &str) -> Option<SystemTime> {
    let mut parts = text.split_ascii_whitespace();
    let weekday = parts.next()?;
    let day: u32 = parts.next()?.parse().ok()?;
    let month = parts.next()?;
    let year: i64 = parts.next()?.parse().ok()?;
    let time = parts.next()?;
    if parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }
    const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let weekday = weekday.strip_suffix(',')?;
    if !WEEKDAYS.contains(&weekday) {
        return None;
    }
    let month = 1 + MONTHS.iter().position(|&m| m == month)? as u32;
    if !(1..=days_in_month(year, month)).contains(&day) || year < 1970 {
        return None;
    }

    let mut clock = time.split(':');
    let hour: u64 = two_digits(clock.next()?)?;
    let minute: u64 = two_digits(clock.next()?)?;
    let second: u64 = two_digits(clock.next()?)?;
    // 60 is a leap second.
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let days = u64::try_from(days_from_civil(year, month, day)).ok()?;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
}

/// Parses exactly two digits.
fn two_digits(text: &str) -> Option<u64> {
    if text.len() == 2 && text.bytes().all(|b| b.is_ascii_digit()) {
        text.parse().ok()
    } else {
        None
    }
}

/// Returns the number of days in a month of the proleptic Gregorian
/// calendar.
fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 31,
    }
}

/// Returns the days from 1970-01-01 to a date in the proleptic Gregorian
/// calendar.
///
/// The function is the `days_from_civil` algorithm of Howard Hinnant.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_from_march + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Counts what went wrong for one request and decides whether to go on.
#[derive(Clone, Debug)]
pub(crate) struct Attempts {
    /// 429 responses in a row.
    rate_limited: u32,
    /// 5xx responses and network errors so far.
    failures: usize,
    /// The pause before each retry after a failure. The number of pauses is
    /// the number of retries.
    pauses: Vec<Duration>,
}

impl Attempts {
    /// Starts counting for a new request.
    pub(crate) fn new(pauses: &[Duration]) -> Self {
        Self {
            rate_limited: 0,
            failures: 0,
            pauses: pauses.to_vec(),
        }
    }

    /// Records a 429 that asks for `wait`.
    ///
    /// Returns `true` if the request waits and tries again, or `false` if it
    /// gives up.
    pub(crate) fn rate_limited(&mut self, wait: Duration) -> bool {
        self.rate_limited += 1;
        wait <= MAX_RATE_LIMIT_WAIT && self.rate_limited <= MAX_RATE_LIMITED
    }

    /// Records a 5xx or a network error.
    ///
    /// Returns the pause before the next attempt, or `None` if the retries
    /// are spent.
    pub(crate) fn failed(&mut self) -> Option<Duration> {
        // A failure breaks a run of 429s.
        self.rate_limited = 0;
        let pause = self.pauses.get(self.failures).copied();
        self.failures += 1;
        pause
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1994-11-06 08:49:37 UTC, the example of RFC 9110.
    fn rfc_example() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_777)
    }

    #[test]
    fn seconds() {
        let now = SystemTime::now();
        assert_eq!(retry_after(Some("120"), now), Duration::from_secs(120));
        assert_eq!(retry_after(Some(" 0 "), now), Duration::ZERO);
        assert_eq!(
            retry_after(Some("99999999999999999999999"), now),
            Duration::MAX
        );
    }

    #[test]
    fn missing_or_unreadable_is_a_minute() {
        let now = SystemTime::now();
        assert_eq!(retry_after(None, now), Duration::from_secs(60));
        assert_eq!(retry_after(Some(""), now), Duration::from_secs(60));
        assert_eq!(retry_after(Some("-5"), now), Duration::from_secs(60));
        assert_eq!(retry_after(Some("soon"), now), Duration::from_secs(60));
        // RFC 850 and asctime forms are obsolete.
        assert_eq!(
            retry_after(Some("Sunday, 06-Nov-94 08:49:37 GMT"), now),
            Duration::from_secs(60)
        );
        assert_eq!(
            retry_after(Some("Sun Nov  6 08:49:37 1994"), now),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn dates() {
        assert_eq!(
            imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(rfc_example())
        );
        assert_eq!(
            imf_fixdate("Thu, 01 Jan 1970 00:00:00 GMT"),
            Some(SystemTime::UNIX_EPOCH)
        );
        assert_eq!(
            imf_fixdate("Thu, 29 Feb 2024 12:00:00 GMT"),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_709_208_000))
        );
        for bad in [
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 31 Nov 1994 08:49:37 GMT",
            "Fri, 29 Feb 2023 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:00:00 GMT",
            "Sun, 06 Nov 1994 8:49:37 GMT",
            "Sun 06 Nov 1994 08:49:37 GMT",
            "Xyz, 06 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37 GMT extra",
        ] {
            assert_eq!(imf_fixdate(bad), None, "{bad}");
        }
    }

    #[test]
    fn dates_are_relative_to_now() {
        let now = rfc_example();
        assert_eq!(
            retry_after(Some("Sun, 06 Nov 1994 08:51:37 GMT"), now),
            Duration::from_secs(120)
        );
        assert_eq!(
            retry_after(Some("Sun, 06 Nov 1994 08:00:00 GMT"), now),
            Duration::ZERO
        );
    }

    #[test]
    fn sixth_429_in_a_row_gives_up() {
        let mut attempts = Attempts::new(&RETRY_PAUSES);
        for _ in 0..5 {
            assert!(attempts.rate_limited(Duration::from_secs(60)));
        }
        assert!(!attempts.rate_limited(Duration::from_secs(60)));

        let mut attempts = Attempts::new(&RETRY_PAUSES);
        for _ in 0..5 {
            assert!(attempts.rate_limited(Duration::ZERO));
        }
        // A 5xx in between starts the count again.
        assert_eq!(attempts.failed(), Some(Duration::from_secs(1)));
        assert!(attempts.rate_limited(Duration::ZERO));
    }

    #[test]
    fn pauses_over_an_hour_give_up() {
        let mut attempts = Attempts::new(&RETRY_PAUSES);
        assert!(attempts.rate_limited(Duration::from_secs(3600)));
        assert!(!attempts.rate_limited(Duration::from_secs(3601)));
    }
}

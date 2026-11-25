//! UTC timestamps used by gateway configuration and wire contracts.

use ::time::format_description::{well_known::Rfc3339, BorrowedFormatItem};
use ::time::macros::format_description;
use ::time::OffsetDateTime;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{self, Write};
use std::ops::{Add, AddAssign, Sub};
use std::str::FromStr;

pub use jiff::SignedDuration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    pub fn from_timestamp(seconds: i64, nanoseconds: u32) -> Option<Self> {
        if nanoseconds >= 1_000_000_000 {
            return None;
        }
        let total = i128::from(seconds) * 1_000_000_000 + i128::from(nanoseconds);
        OffsetDateTime::from_unix_timestamp_nanos(total)
            .ok()
            .map(Self)
    }

    pub fn parse_from_rfc3339(value: &str) -> Result<Self, ::time::Error> {
        value.parse()
    }

    pub fn timestamp(self) -> i64 {
        self.0.unix_timestamp()
    }

    pub fn timestamp_millis(self) -> i64 {
        self.0.unix_timestamp_nanos().div_euclid(1_000_000) as i64
    }

    pub(crate) fn format(self, pattern: &[BorrowedFormatItem<'_>]) -> String {
        self.0.format(pattern).expect("valid timestamp format")
    }

    pub fn to_rfc3339(self) -> String {
        self.format_rfc3339(None, "+00:00")
    }

    #[cfg(test)]
    pub(crate) fn to_rfc3339_micros(self) -> String {
        self.format_rfc3339(Some(6), "Z")
    }

    fn format_rfc3339(self, precision: Option<usize>, offset: &str) -> String {
        let nanos = self.0.nanosecond();
        // Existing snapshots and receipts use whole, milli, micro, or nanosecond precision.
        let digits = precision.unwrap_or(if nanos == 0 {
            0
        } else if nanos.is_multiple_of(1_000_000) {
            3
        } else if nanos.is_multiple_of(1_000) {
            6
        } else {
            9
        });
        let mut result = self.format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]"
        ));
        if digits != 0 {
            let fraction = nanos / 10_u32.pow((9 - digits) as u32);
            write!(result, ".{fraction:0digits$}").expect("format string");
        }
        result.push_str(offset);
        result
    }
}

impl FromStr for Timestamp {
    type Err = ::time::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = OffsetDateTime::parse(value, &Rfc3339)?;
        Ok(Self(OffsetDateTime::from_unix_timestamp_nanos(
            parsed.unix_timestamp_nanos(),
        )?))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format_rfc3339(None, "Z"))
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.format_rfc3339(None, "Z"))
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl Add<SignedDuration> for Timestamp {
    type Output = Self;

    fn add(self, duration: SignedDuration) -> Self {
        let nanos = self.0.unix_timestamp_nanos() + duration.as_nanos();
        Self(OffsetDateTime::from_unix_timestamp_nanos(nanos).expect("timestamp out of range"))
    }
}

impl AddAssign<SignedDuration> for Timestamp {
    fn add_assign(&mut self, duration: SignedDuration) {
        *self = *self + duration;
    }
}

impl Sub<SignedDuration> for Timestamp {
    type Output = Self;

    fn sub(self, duration: SignedDuration) -> Self {
        let nanos = self.0.unix_timestamp_nanos() - duration.as_nanos();
        Self(OffsetDateTime::from_unix_timestamp_nanos(nanos).expect("timestamp out of range"))
    }
}

impl Sub for Timestamp {
    type Output = SignedDuration;

    fn sub(self, other: Self) -> SignedDuration {
        SignedDuration::from_nanos_i128(
            self.0.unix_timestamp_nanos() - other.0.unix_timestamp_nanos(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_wire_timestamps_keep_their_canonical_precision() {
        for time in [
            "2025-06-03T09:08:07Z",
            "2025-06-03T09:08:07.120Z",
            "2025-06-03T09:08:07.120300Z",
            "2025-06-03T09:08:07.120300001Z",
            "1969-12-31T23:59:59.999Z",
            "9999-12-31T23:59:59.999999999Z",
        ] {
            let decoded: Timestamp = serde_json::from_str(&format!("\"{time}\"")).unwrap();
            assert_eq!(
                serde_json::to_string(&decoded).unwrap(),
                format!("\"{time}\"")
            );
            assert_eq!(decoded.to_rfc3339(), time.replace('Z', "+00:00"));
        }

        let offset: Timestamp = "1970-01-01T00:59:59.999+01:00".parse().unwrap();
        assert_eq!(offset.timestamp(), -1);
        assert_eq!(offset.timestamp_millis(), -1);
        assert_eq!(
            serde_json::to_string(&offset).unwrap(),
            "\"1969-12-31T23:59:59.999Z\""
        );
    }
}

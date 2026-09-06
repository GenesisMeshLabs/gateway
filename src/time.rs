//! Timestamp rendering that matches Pydantic's JSON mode.
//!
//! Signatures cover the canonical JSON, and timestamps are part of that, so the
//! textual form has to match Python byte for byte. Observed from the reference
//! implementation:
//!
//! ```text
//! 2026-01-01T12:00:00Z           whole seconds  -> no fractional part
//! 2026-01-01T12:00:00.123456Z    sub-second     -> exactly 6 digits
//! ```
//!
//! Always `Z`, never `+00:00`.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serializer};

/// Render a UTC timestamp the way Pydantic does in JSON mode.
pub fn format(dt: &DateTime<Utc>) -> String {
    if dt.timestamp_subsec_micros() == 0 {
        dt.to_rfc3339_opts(SecondsFormat::Secs, true)
    } else {
        dt.to_rfc3339_opts(SecondsFormat::Micros, true)
    }
}

/// serde adapter: `#[serde(with = "crate::time::py_datetime")]`.
pub mod py_datetime {
    use super::*;

    /// Serialize in the Python reference timestamp format.
    pub fn serialize<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::format(dt))
    }

    /// Parse the signed timestamp.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let raw = String::deserialize(d)?;
        DateTime::parse_from_rfc3339(&raw)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn whole_seconds_have_no_fraction() {
        let dt = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();
        assert_eq!(format(&dt), "2026-01-01T12:00:00Z");
    }

    #[test]
    fn sub_second_uses_six_digits() {
        let dt = Utc
            .with_ymd_and_hms(2026, 1, 8, 12, 30, 45)
            .unwrap()
            .with_timezone(&Utc)
            + chrono::Duration::microseconds(500_000);
        assert_eq!(format(&dt), "2026-01-08T12:30:45.500000Z");
    }
}

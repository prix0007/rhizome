//! Validation of the user-supplied device metadata (`PUT /api/devices/{id}/meta`).

use crate::enrich::sanitize::{sanitize, sanitize_multiline};
use crate::model::UserMeta;

pub const MAX_BODY_BYTES: usize = 4 * 1024;
pub const MAX_NAME_CHARS: usize = 64;
pub const MAX_NOTES_CHARS: usize = 500;

/// What to do with one field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The key was absent: leave the stored value alone.
    Keep,
    /// `null` or an empty/whitespace-only string.
    Clear,
    Set(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaUpdate {
    pub custom_name: Change,
    pub notes: Change,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum MetaError {
    #[error("body is not valid JSON")]
    Malformed,
    #[error("body must be a JSON object with only custom_name and notes")]
    Shape,
    #[error("{0} must be a string or null")]
    Type(&'static str),
    #[error("{0} is too long (max {1} characters)")]
    TooLong(&'static str, usize),
}

/// Parse and validate a request body. Strings are sanitised like all other
/// text; over-long values are rejected rather than silently truncated.
pub fn parse_meta_update(body: &[u8]) -> Result<MetaUpdate, MetaError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| MetaError::Malformed)?;
    let obj = value.as_object().ok_or(MetaError::Shape)?;
    if obj.keys().any(|k| k != "custom_name" && k != "notes") {
        return Err(MetaError::Shape);
    }
    Ok(MetaUpdate {
        custom_name: field(obj.get("custom_name"), "custom_name", MAX_NAME_CHARS, false)?,
        notes: field(obj.get("notes"), "notes", MAX_NOTES_CHARS, true)?,
    })
}

fn field(
    v: Option<&serde_json::Value>,
    name: &'static str,
    max: usize,
    multiline: bool,
) -> Result<Change, MetaError> {
    match v {
        None => Ok(Change::Keep),
        Some(serde_json::Value::Null) => Ok(Change::Clear),
        Some(serde_json::Value::String(s)) => {
            if s.chars().count() > max {
                return Err(MetaError::TooLong(name, max));
            }
            let clean = if multiline {
                sanitize_multiline(s, max)
            } else {
                sanitize(s)
            };
            Ok(if clean.is_empty() {
                Change::Clear
            } else {
                Change::Set(clean)
            })
        }
        Some(_) => Err(MetaError::Type(name)),
    }
}

impl MetaUpdate {
    /// Apply to the current value; the result is what should be stored.
    pub fn apply(&self, current: &UserMeta) -> UserMeta {
        let pick = |change: &Change, cur: &Option<String>| match change {
            Change::Keep => cur.clone(),
            Change::Clear => None,
            Change::Set(v) => Some(v.clone()),
        };
        UserMeta {
            custom_name: pick(&self.custom_name, &current.custom_name),
            notes: pick(&self.notes, &current.notes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<MetaUpdate, MetaError> {
        parse_meta_update(s.as_bytes())
    }

    #[test]
    fn sets_and_clears() {
        let u = p(r#"{"custom_name":"Living room TV","notes":"Bought 2023"}"#).unwrap();
        assert_eq!(u.custom_name, Change::Set("Living room TV".into()));
        assert_eq!(u.notes, Change::Set("Bought 2023".into()));
        let u = p(r#"{"custom_name":null,"notes":""}"#).unwrap();
        assert_eq!((u.custom_name, u.notes), (Change::Clear, Change::Clear));
        let u = p(r#"{"custom_name":"   ","notes":null}"#).unwrap();
        assert_eq!((u.custom_name, u.notes), (Change::Clear, Change::Clear));
    }

    #[test]
    fn absent_keys_leave_the_value_alone() {
        let u = p(r#"{"notes":"x"}"#).unwrap();
        assert_eq!(u.custom_name, Change::Keep);
        let u = p("{}").unwrap();
        assert_eq!((u.custom_name, u.notes), (Change::Keep, Change::Keep));
    }

    #[test]
    fn strings_are_sanitised() {
        let u = p("{\"custom_name\":\"a\\u0000b\\u001b[31m\\u202ec\\n d\"}").unwrap();
        assert_eq!(u.custom_name, Change::Set("ab[31mc d".into()));
        let u = p("{\"notes\":\"line1\\r\\nline2\\n\\n\\nline3\\u0007\"}").unwrap();
        assert_eq!(
            u.notes,
            Change::Set("line1\nline2\n\nline3".into()),
            "newlines survive in notes only"
        );
    }

    #[test]
    fn length_limits_are_enforced_in_characters() {
        let name64 = "é".repeat(64);
        assert!(p(&format!(r#"{{"custom_name":"{name64}"}}"#)).is_ok());
        let name65 = "é".repeat(65);
        assert_eq!(
            p(&format!(r#"{{"custom_name":"{name65}"}}"#)),
            Err(MetaError::TooLong("custom_name", 64))
        );
        let n500 = "n".repeat(500);
        assert!(p(&format!(r#"{{"notes":"{n500}"}}"#)).is_ok());
        let n501 = "n".repeat(501);
        assert_eq!(
            p(&format!(r#"{{"notes":"{n501}"}}"#)),
            Err(MetaError::TooLong("notes", 500))
        );
    }

    #[test]
    fn malformed_or_wrongly_shaped_bodies_are_rejected() {
        assert_eq!(p(""), Err(MetaError::Malformed));
        assert_eq!(p("{"), Err(MetaError::Malformed));
        assert_eq!(p("not json"), Err(MetaError::Malformed));
        assert_eq!(parse_meta_update(&[0xff, 0xfe]), Err(MetaError::Malformed));
        for body in ["[]", "null", "\"x\"", "42", "true"] {
            assert_eq!(p(body), Err(MetaError::Shape), "{body}");
        }
        assert_eq!(
            p(r#"{"custom_name":"a","hostname":"b"}"#),
            Err(MetaError::Shape)
        );
        assert_eq!(
            p(r#"{"custom_name":5}"#),
            Err(MetaError::Type("custom_name"))
        );
        assert_eq!(p(r#"{"notes":["a"]}"#), Err(MetaError::Type("notes")));
        assert_eq!(p(r#"{"notes":{"a":1}}"#), Err(MetaError::Type("notes")));
    }

    #[test]
    fn apply_keeps_sets_and_clears() {
        let cur = UserMeta {
            custom_name: Some("old".into()),
            notes: Some("n".into()),
        };
        let u = MetaUpdate {
            custom_name: Change::Keep,
            notes: Change::Clear,
        };
        assert_eq!(
            u.apply(&cur),
            UserMeta {
                custom_name: Some("old".into()),
                notes: None
            }
        );
        let u = MetaUpdate {
            custom_name: Change::Set("new".into()),
            notes: Change::Keep,
        };
        assert_eq!(
            u.apply(&cur),
            UserMeta {
                custom_name: Some("new".into()),
                notes: Some("n".into())
            }
        );
    }
}

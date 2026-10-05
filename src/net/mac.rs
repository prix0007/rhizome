//! MAC address parsing and classification. macOS prints octets without
//! zero-padding (`0:1a:2b:3:4:5`), so parsing accepts 1 or 2 hex digits.

use std::fmt;
use std::str::FromStr;

use crate::model::MacAddr;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid MAC address")]
pub struct MacParseError;

impl FromStr for MacAddr {
    type Err = MacParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0u8; 6];
        let mut parts = s.split([':', '-']);
        for slot in out.iter_mut() {
            let p = parts.next().ok_or(MacParseError)?;
            if p.is_empty() || p.len() > 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(MacParseError);
            }
            *slot = u8::from_str_radix(p, 16).map_err(|_| MacParseError)?;
        }
        if parts.next().is_some() {
            return Err(MacParseError);
        }
        Ok(MacAddr(out))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            o[0], o[1], o[2], o[3], o[4], o[5]
        )
    }
}

impl MacAddr {
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; 6]
    }
    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }
    /// First three octets as a 24-bit OUI key.
    pub fn oui(&self) -> u32 {
        u32::from_be_bytes([0, self.0[0], self.0[1], self.0[2]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_octets_normalise_to_padded_lowercase() {
        let m: MacAddr = "0:1a:2b:3:4:5".parse().unwrap();
        assert_eq!(m.to_string(), "00:1a:2b:03:04:05");
    }

    #[test]
    fn uppercase_input_is_accepted() {
        let m: MacAddr = "AA:BB:CC:DD:EE:FF".parse().unwrap();
        assert_eq!(m.to_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn dash_separator_is_accepted() {
        let m: MacAddr = "aa-bb-cc-dd-ee-ff".parse().unwrap();
        assert_eq!(m.0, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        for bad in [
            "",
            "(incomplete)",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "aa:bb:cc:dd:ee:gg",
            "aaa:bb:cc:dd:ee:ff",
            "aa:bb:cc:dd:ee:",
            "::::::",
            "aa:bb:cc:dd:ee:ff\n",
            "ü:bb:cc:dd:ee:ff",
        ] {
            assert!(
                bad.parse::<MacAddr>().is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn multicast_and_broadcast_flags() {
        let mc: MacAddr = "1:0:5e:0:0:fb".parse().unwrap();
        assert!(mc.is_multicast());
        assert!(!mc.is_broadcast());
        let bc: MacAddr = "ff:ff:ff:ff:ff:ff".parse().unwrap();
        assert!(bc.is_multicast() && bc.is_broadcast());
        let uc: MacAddr = "68:7f:f0:00:00:01".parse().unwrap();
        assert!(!uc.is_multicast());
    }

    #[test]
    fn locally_administered_is_the_0x02_bit() {
        let la: MacAddr = "2:0:0:0:0:62".parse().unwrap();
        assert!(la.is_locally_administered());
        let la2: MacAddr = "32:00:00:00:00:84".parse().unwrap();
        assert!(la2.is_locally_administered());
        let global: MacAddr = "68:7f:f0:00:00:01".parse().unwrap();
        assert!(!global.is_locally_administered());
    }

    #[test]
    fn zero_and_oui() {
        assert!(MacAddr([0; 6]).is_zero());
        let m: MacAddr = "68:7f:f0:00:00:01".parse().unwrap();
        assert_eq!(m.oui(), 0x687FF0);
    }

    #[test]
    fn serde_round_trip_uses_string_form() {
        let m: MacAddr = "0:1a:2b:3:4:5".parse().unwrap();
        let j = serde_json::to_string(&m).unwrap();
        assert_eq!(j, "\"00:1a:2b:03:04:05\"");
        assert_eq!(serde_json::from_str::<MacAddr>(&j).unwrap(), m);
    }
}

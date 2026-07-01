//! Minimal WhatsApp JID parsing — enough to pull the `username` and `device` for the login payload.
//!
//! Our own device JID after pairing looks like `user[.agent][:device]@server`, e.g.
//! `447700900123:23@s.whatsapp.net` (device 23) or `447700900123.0:23@s.whatsapp.net`.

use crate::Error;

/// A parsed JID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jid {
    pub user: u64,
    pub agent: u8,
    pub device: u16,
    pub server: String,
}

/// Parse a JID string. The user part must be numeric (our own account JID always is).
pub fn parse_jid(s: &str) -> Result<Jid, Error> {
    let (user_part, server) = s.split_once('@').ok_or(Error::Pairing("jid missing '@'"))?;
    let (before_device, device) = match user_part.split_once(':') {
        Some((u, d)) => (u, d.parse::<u16>().map_err(|_| Error::Pairing("jid device not numeric"))?),
        None => (user_part, 0),
    };
    let (user_str, agent) = match before_device.split_once('.') {
        Some((u, a)) => (u, a.parse::<u8>().unwrap_or(0)),
        None => (before_device, 0),
    };
    let user = user_str.parse::<u64>().map_err(|_| Error::Pairing("jid user not numeric"))?;
    Ok(Jid {
        user,
        agent,
        device,
        server: server.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_user_device() {
        let j = parse_jid("447700900123:23@s.whatsapp.net").unwrap();
        assert_eq!(j.user, 447_700_900_123);
        assert_eq!(j.device, 23);
        assert_eq!(j.server, "s.whatsapp.net");
    }

    #[test]
    fn parses_user_agent_device() {
        let j = parse_jid("12345.0:5@s.whatsapp.net").unwrap();
        assert_eq!((j.user, j.agent, j.device), (12345, 0, 5));
    }

    #[test]
    fn parses_bare_user() {
        let j = parse_jid("999@s.whatsapp.net").unwrap();
        assert_eq!((j.user, j.device), (999, 0));
    }

    #[test]
    fn rejects_non_numeric_user() {
        assert!(parse_jid("abc@s.whatsapp.net").is_err());
    }
}

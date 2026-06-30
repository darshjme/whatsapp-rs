//! Minimal protobuf wire primitives (varint + length-delimited fields).
//!
//! WhatsApp's wire types are protobufs. Rather than pull a full code-generated stack (and a `protoc`
//! build dependency) before we need it, this module provides just enough of the binary protobuf
//! encoding to read and write the handful of message types the handshake and login require. It can
//! be swapped for generated `prost` types later without changing the public `waproto` API.

use crate::Error;

/// Protobuf wire types we handle.
mod wire {
    pub const VARINT: u64 = 0;
    pub const I64: u64 = 1;
    pub const LEN: u64 = 2;
    pub const I32: u64 = 5;
}

/// Append a base-128 varint.
pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

/// Append a length-delimited (wire type 2) field: tag, length, bytes.
pub fn put_len_field(out: &mut Vec<u8>, field_no: u64, data: &[u8]) {
    put_varint(out, (field_no << 3) | wire::LEN);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

/// Append a varint (wire type 0) field: tag, value. Use for bool/enum/int fields.
pub fn put_varint_field(out: &mut Vec<u8>, field_no: u64, value: u64) {
    put_varint(out, (field_no << 3) | wire::VARINT);
    put_varint(out, value);
}

/// Read a base-128 varint, advancing `pos`.
pub fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, Error> {
    let mut shift = 0u32;
    let mut val = 0u64;
    loop {
        let b = *data.get(*pos).ok_or(Error::Eof)?;
        *pos += 1;
        val |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(val);
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::Malformed("varint exceeds 64 bits"));
        }
    }
}

/// A decoded length-delimited field: its field number and raw bytes.
pub type LenField = (u64, Vec<u8>);

/// Walk a message, returning every length-delimited (wire type 2) field as `(field_no, bytes)`.
/// Other wire types are skipped (their values are consumed but not returned).
pub fn iter_len_fields(data: &[u8]) -> Result<Vec<LenField>, Error> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let key = read_varint(data, &mut pos)?;
        let field_no = key >> 3;
        match key & 7 {
            wire::LEN => {
                let len = read_varint(data, &mut pos)? as usize;
                let end = pos.checked_add(len).ok_or(Error::Eof)?;
                let slice = data.get(pos..end).ok_or(Error::Eof)?;
                out.push((field_no, slice.to_vec()));
                pos = end;
            }
            wire::VARINT => {
                read_varint(data, &mut pos)?;
            }
            wire::I64 => pos = pos.checked_add(8).ok_or(Error::Eof)?,
            wire::I32 => pos = pos.checked_add(4).ok_or(Error::Eof)?,
            other => return Err(Error::UnsupportedWireType(other)),
        }
    }
    Ok(out)
}

/// Find the first length-delimited field with the given number.
pub fn get_field(fields: &[LenField], field_no: u64) -> Option<&[u8]> {
    fields
        .iter()
        .find(|(f, _)| *f == field_no)
        .map(|(_, b)| b.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trips() {
        for v in [0u64, 1, 127, 128, 300, 16384, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            put_varint(&mut buf, v);
            let mut pos = 0;
            assert_eq!(read_varint(&buf, &mut pos).unwrap(), v);
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn len_fields_round_trip() {
        let mut buf = Vec::new();
        put_len_field(&mut buf, 1, b"abc");
        put_len_field(&mut buf, 3, b"defgh");
        let fields = iter_len_fields(&buf).unwrap();
        assert_eq!(get_field(&fields, 1), Some(&b"abc"[..]));
        assert_eq!(get_field(&fields, 3), Some(&b"defgh"[..]));
        assert_eq!(get_field(&fields, 2), None);
    }
}

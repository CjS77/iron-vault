//! The field layer every body except owner input uses: a `u16` tag, a `u32` length and the value, with tags strictly
//! ascending so each body has exactly one encoding.

use super::FrameError;

/// The size of a field's tag and length.
pub(super) const FIELD_HEADER_LEN: usize = 6;

/// One field of a decoded body, borrowing its value from the body.
pub(super) struct Field<'a> {
    tag: u16,
    value: &'a [u8],
}

/// Appends one field. Callers keep the whole body within the frame bound, so the length always fits a `u32`; a value
/// that did not would be refused by the frame bound anyway, so it saturates rather than wrapping.
pub(super) fn put(out: &mut Vec<u8>, tag: u16, value: &[u8]) {
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(value);
}

/// Splits a body into fields, refusing a field that runs past the end and any tag not above the one before it.
pub(super) fn parse(body: &[u8]) -> Result<Vec<Field<'_>>, FrameError> {
    let mut rest = body;
    let fields = std::iter::from_fn(|| {
        (!rest.is_empty()).then(|| {
            split_field(rest).map(|(field, after)| {
                rest = after;
                field
            })
        })
    })
    .collect::<Result<Vec<_>, _>>()?;
    fields.windows(2).try_for_each(|pair| match pair {
        [before, after] if after.tag == before.tag => Err(FrameError::DuplicateTag(after.tag)),
        [before, after] if after.tag < before.tag => Err(FrameError::TagOutOfOrder(after.tag)),
        _ => Ok(()),
    })?;
    Ok(fields)
}

/// The values of exactly the fields `tags` names, in order: any other tag, or a missing one, is an error. `tags` must be
/// ascending, as the fields already are.
pub(super) fn exact<'a, const N: usize>(fields: &[Field<'a>], tags: [u16; N]) -> Result<[&'a [u8]; N], FrameError> {
    if let Some(unknown) = fields.iter().find(|field| !tags.contains(&field.tag)) {
        return Err(FrameError::UnknownTag(unknown.tag));
    }
    let mut values = [&[][..]; N];
    tags.iter().zip(values.iter_mut()).try_for_each(|(tag, value)| {
        *value = fields
            .iter()
            .find(|field| field.tag == *tag)
            .ok_or(FrameError::MissingField(*tag))?
            .value;
        Ok(())
    })?;
    Ok(values)
}

/// The value of the first field, which must carry `tag`.
pub(super) fn first<'a>(fields: &[Field<'a>], tag: u16) -> Result<&'a [u8], FrameError> {
    fields
        .first()
        .filter(|field| field.tag == tag)
        .map(|field| field.value)
        .ok_or(FrameError::MissingField(tag))
}

/// A `u16` field value, which must be exactly two bytes.
pub(super) fn read_u16(tag: u16, value: &[u8]) -> Result<u16, FrameError> {
    <[u8; 2]>::try_from(value)
        .map(u16::from_be_bytes)
        .map_err(|_| FrameError::InvalidValue(tag))
}

/// A flag field value: exactly one byte, 0 or 1.
pub(super) fn read_flag(tag: u16, value: &[u8]) -> Result<bool, FrameError> {
    match value {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(FrameError::InvalidValue(tag)),
    }
}

/// A text field value, which must be UTF-8.
pub(super) fn read_text(tag: u16, value: &[u8]) -> Result<String, FrameError> {
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| FrameError::InvalidUtf8(tag))
}

fn split_field(bytes: &[u8]) -> Result<(Field<'_>, &[u8]), FrameError> {
    let (header, rest) = bytes.split_first_chunk::<FIELD_HEADER_LEN>().ok_or(FrameError::TruncatedField)?;
    let [t0, t1, l0, l1, l2, l3] = *header;
    let len = usize::try_from(u32::from_be_bytes([l0, l1, l2, l3])).map_err(|_| FrameError::TruncatedField)?;
    let (value, rest) = rest.split_at_checked(len).ok_or(FrameError::TruncatedField)?;
    let tag = u16::from_be_bytes([t0, t1]);
    Ok((Field { tag, value }, rest))
}

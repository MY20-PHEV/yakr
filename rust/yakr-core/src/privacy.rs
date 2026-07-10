pub const MODE_FAST: &str = "fast";
pub const MODE_BALANCED: &str = "balanced";
pub const MODE_HIGH: &str = "high";

pub const SIZE_4K: usize = 4096;
pub const SIZE_32K: usize = 32768;

fn size_classes(mode: &str) -> Vec<usize> {
    match mode {
        MODE_HIGH => vec![SIZE_4K, SIZE_32K],
        MODE_BALANCED => vec![SIZE_4K],
        _ => vec![],
    }
}

fn select_size_class(plaintext_len: usize, mode: &str) -> Option<usize> {
    if mode == MODE_FAST {
        return None;
    }
    let classes = size_classes(mode);
    let needed = plaintext_len + 4;
    for class_size in classes.iter().copied() {
        if needed <= class_size {
            return Some(class_size);
        }
    }
    classes.into_iter().max()
}

pub fn pad_plaintext(plaintext: &[u8], mode: &str) -> Result<(Vec<u8>, usize), String> {
    let Some(class_size) = select_size_class(plaintext.len(), mode) else {
        return Ok((plaintext.to_vec(), 0));
    };
    let mut framed = Vec::with_capacity(4 + plaintext.len());
    framed.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    framed.extend_from_slice(plaintext);
    if framed.len() > class_size {
        return Err("plaintext exceeds maximum size class".into());
    }
    framed.resize(class_size, 0);
    Ok((framed, class_size - plaintext.len()))
}

pub fn unpad_plaintext(padded: &[u8]) -> Result<Vec<u8>, String> {
    if padded.len() < 4 {
        return Err("padded payload too short".into());
    }
    let length = u32::from_be_bytes(padded[..4].try_into().unwrap()) as usize;
    let end = 4 + length;
    if end > padded.len() {
        return Err("invalid padded length prefix".into());
    }
    Ok(padded[4..end].to_vec())
}

pub fn decode_padded_plaintext(data: &[u8], mode: &str) -> Result<Vec<u8>, String> {
    if mode == MODE_FAST {
        return Ok(data.to_vec());
    }
    unpad_plaintext(data)
}

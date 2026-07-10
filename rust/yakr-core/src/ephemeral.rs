pub const MESSAGE_TTL_MS: u64 = 24 * 60 * 60 * 1000;
pub const DEFAULT_BLOB_TTL_MS: u64 = MESSAGE_TTL_MS;
pub const MAX_RELAY_BLOB_TTL_MS: u64 = MESSAGE_TTL_MS;

pub fn message_valid_until(created_at_ms: u64) -> u64 {
    created_at_ms.saturating_add(MESSAGE_TTL_MS)
}

pub fn enforce_message_ttl(valid_until: u64) -> crate::error::Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if valid_until <= now {
        return Err(crate::error::YakrError::MessageExpired);
    }
    Ok(())
}

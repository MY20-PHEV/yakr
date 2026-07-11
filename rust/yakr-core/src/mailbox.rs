use std::time::{SystemTime, UNIX_EPOCH};

use yakr_crypto::derive_mailbox_secret;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxTag {
    pub tag: [u8; 32],
    pub epoch: u64,
    pub direction: String,
}

pub fn current_epoch(epoch_secs: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now / epoch_secs
}

pub struct MailboxTagDeriver {
    secret: [u8; 32],
    epoch_secs: u64,
}

impl MailboxTagDeriver {
    pub fn new(mailbox_secret: [u8; 32], epoch_secs: u64) -> Self {
        Self {
            secret: mailbox_secret,
            epoch_secs,
        }
    }

    pub fn from_master(master_secret: &[u8], direction: &str, epoch_secs: u64) -> Self {
        Self::new(derive_mailbox_secret(master_secret, direction), epoch_secs)
    }

    pub fn derive(&self, direction: &str, epoch: Option<u64>) -> MailboxTag {
        let epoch_value = epoch.unwrap_or_else(|| current_epoch(self.epoch_secs));
        let tag = yakr_crypto::mailbox_tag_from_secret(&self.secret, direction, epoch_value);
        MailboxTag {
            tag,
            epoch: epoch_value,
            direction: direction.to_string(),
        }
    }

    pub fn candidate_epochs(&self, direction: &str, lookback: u64) -> Vec<MailboxTag> {
        let now = current_epoch(self.epoch_secs);
        (0..=lookback)
            .map(|offset| self.derive(direction, Some(now - offset)))
            .collect()
    }
}

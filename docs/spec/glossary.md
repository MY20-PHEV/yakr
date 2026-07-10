# Yakr Glossary

| Term | Definition |
|------|------------|
| **Identity** | Long-term user key material (signing + agreement keys) |
| **Device** | A client endpoint with its own device ID derived from signing key |
| **Contact** | Pairwise relationship with shared master secret and conversation state |
| **Session** | Encrypt/decrypt operations for a single contact relationship |
| **Outer blob** | Relay-visible encrypted packet (tag, expiry, ciphertext) |
| **Inner message** | Recipient-only plaintext payload after decryption |
| **Mailbox tag** | Opaque HMAC tag used to store/fetch blobs without revealing recipient identity |
| **Relay** | Store-and-forward node that handles opaque blobs only |
| **Mailbox relay** | Relay that stores blobs under mailbox tags |
| **Platform wake** | Optional silent push (APNs/FCM) that hints the client to fetch; not part of delivery correctness |
| **Wake gateway** | Service holding platform push credentials; relays send wake requests with device tokens only |
| **Direction** | Sender→recipient string used to derive directional mailbox secrets |

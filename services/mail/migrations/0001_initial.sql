CREATE TABLE IF NOT EXISTS mail_messages (
    said TEXT PRIMARY KEY,
    source_node_prefix TEXT NOT NULL,
    recipient_kel_prefix TEXT NOT NULL,
    blob_digest TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mail_recipient ON mail_messages(recipient_kel_prefix, created_at);
CREATE INDEX IF NOT EXISTS idx_mail_expires ON mail_messages(expires_at);

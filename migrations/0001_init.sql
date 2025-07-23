CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_guid UUID NOT NULL,
    session_id UUID NOT NULL,
    token_hash TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    ip_address TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    is_valid BOOLEAN NOT NULL DEFAULT TRUE
)
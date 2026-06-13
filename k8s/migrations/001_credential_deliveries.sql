-- Remise temporaire et a usage unique des identifiants initiaux.
CREATE TABLE IF NOT EXISTS credential_deliveries (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- Le jeton brut reste uniquement dans le QR code. La base conserve son hash.
  token_hash CHAR(64) NOT NULL UNIQUE,

  -- Le mot de passe et l'URI TOTP sont chiffres par l'application.
  password_ciphertext TEXT NOT NULL,
  provisioning_uri_ciphertext TEXT NOT NULL,

  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ NULL,

  CONSTRAINT credential_deliveries_expiry_check
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_credential_deliveries_user_id
  ON credential_deliveries (user_id);

CREATE INDEX IF NOT EXISTS idx_credential_deliveries_expires_at
  ON credential_deliveries (expires_at);

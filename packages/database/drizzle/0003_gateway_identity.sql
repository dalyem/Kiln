CREATE TABLE IF NOT EXISTS gateway_ca (
  singleton integer PRIMARY KEY CHECK (singleton = 1),
  fingerprint text NOT NULL
);
CREATE TABLE IF NOT EXISTS gateway_enrollment_tokens (
  resource_id text PRIMARY KEY REFERENCES gateways(resource_id),
  installation_id text NOT NULL,
  generation text NOT NULL,
  token_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  public_key_fingerprint text,
  device_id text,
  certificate_fingerprint text
);
CREATE TABLE IF NOT EXISTS gateway_identities (
  device_id text PRIMARY KEY,
  resource_id text NOT NULL UNIQUE REFERENCES gateways(resource_id),
  installation_id text NOT NULL,
  generation text NOT NULL,
  public_key_pem text NOT NULL,
  public_key_fingerprint text NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL,
  next_sequence integer NOT NULL CHECK (next_sequence > 0),
  last_seen_at timestamptz,
  last_services text CHECK (last_services IN ('PASS', 'FAIL', 'UNKNOWN')),
  last_policy text CHECK (last_policy IN ('PASS', 'FAIL', 'UNKNOWN')),
  last_reservation text CHECK (last_reservation IN ('PASS', 'FAIL', 'UNKNOWN'))
);
CREATE TABLE IF NOT EXISTS gateway_certificates (
  fingerprint text PRIMARY KEY,
  device_id text NOT NULL REFERENCES gateway_identities(device_id),
  certificate_pem text NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  accepted_until timestamptz NOT NULL,
  current integer NOT NULL CHECK (current IN (0, 1))
);
CREATE UNIQUE INDEX IF NOT EXISTS gateway_certificates_current_one ON gateway_certificates(device_id) WHERE current = 1;
CREATE TABLE IF NOT EXISTS gateway_challenges (
  device_id text PRIMARY KEY REFERENCES gateway_identities(device_id),
  challenge_id text NOT NULL,
  nonce text NOT NULL,
  expires_at timestamptz NOT NULL
);
ALTER TABLE gateway_identities DROP CONSTRAINT IF EXISTS gateway_identities_resource_id_key;
CREATE INDEX IF NOT EXISTS gateway_identities_resource_current ON gateway_identities(resource_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS gateway_identities_one_active ON gateway_identities(resource_id) WHERE revoked_at IS NULL;

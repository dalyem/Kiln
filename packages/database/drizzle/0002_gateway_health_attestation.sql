ALTER TABLE gateway_health ADD COLUMN IF NOT EXISTS generation text;
ALTER TABLE gateway_health ADD COLUMN IF NOT EXISTS expected_fingerprint text;

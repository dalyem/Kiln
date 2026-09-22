-- Keep the initial migration restart-safe: it is re-applied by this pre-release server.
ALTER TABLE resources DROP CONSTRAINT IF EXISTS resources_type_check;
ALTER TABLE resources ADD CONSTRAINT resources_type_check CHECK (type IN ('development', 'execution', 'browser', 'gateway', 'network_probe', 'image_template'));

CREATE TABLE IF NOT EXISTS network_probes (
  resource_id text PRIMARY KEY REFERENCES resources(id),
  installation_id text NOT NULL REFERENCES installations(id),
  gateway_id text NOT NULL REFERENCES gateways(resource_id),
  gateway_generation text NOT NULL,
  gateway_config_fingerprint text NOT NULL,
  node text NOT NULL,
  profile_id text NOT NULL,
  profile_digest text NOT NULL,
  plan jsonb NOT NULL,
  plan_digest text NOT NULL,
  state text NOT NULL CHECK (state IN ('PENDING', 'COMPLETED', 'TIMED_OUT', 'INVALIDATED', 'CANCELLED')),
  token_hash text,
  token_expires_at timestamptz,
  result_digest text,
  results jsonb,
  received_at timestamptz,
  created_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS network_probes_pending_expiry ON network_probes(state, token_expires_at);

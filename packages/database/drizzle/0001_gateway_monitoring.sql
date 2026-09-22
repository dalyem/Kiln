ALTER TABLE resources DROP CONSTRAINT IF EXISTS resources_type_check;
ALTER TABLE resources ADD CONSTRAINT resources_type_check CHECK (type IN ('development', 'execution', 'browser', 'gateway', 'network_probe', 'image_template'));
ALTER TABLE resources DROP CONSTRAINT IF EXISTS resources_gateway_persistent_check;
ALTER TABLE resources ADD CONSTRAINT resources_gateway_persistent_check CHECK (type <> 'gateway' OR expires_at IS NULL);
CREATE TABLE IF NOT EXISTS gateways (
  resource_id text PRIMARY KEY REFERENCES resources(id),
  node text NOT NULL,
  generation text NOT NULL,
  expected_fingerprint text NOT NULL,
  created_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS gateways_node_unique ON gateways(node);
CREATE TABLE IF NOT EXISTS gateway_health (
  resource_id text PRIMARY KEY REFERENCES gateways(resource_id),
  node text NOT NULL,
  status text NOT NULL CHECK (status IN ('READY', 'NOT_READY', 'QUARANTINED', 'UNCONFIGURED')),
  observed_at timestamptz NOT NULL,
  evidence jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS gateway_incidents (
  id text PRIMARY KEY,
  node text NOT NULL,
  gateway_id text REFERENCES gateways(resource_id),
  code text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('warning', 'critical')),
  status text NOT NULL CHECK (status IN ('OPEN', 'RESOLVED')),
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  resolved_at timestamptz,
  message text NOT NULL,
  guidance jsonb NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS gateway_incidents_open_dedup ON gateway_incidents(gateway_id, code) WHERE status = 'OPEN';

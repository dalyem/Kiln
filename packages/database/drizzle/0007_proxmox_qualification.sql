CREATE TABLE IF NOT EXISTS qualification_runs (
  id text PRIMARY KEY,
  installation_id text NOT NULL UNIQUE REFERENCES installations(id) ON DELETE RESTRICT,
  idempotency_key text NOT NULL,
  normalized_payload text NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE', 'COMPLETED', 'UNKNOWN')),
  plan jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  completed_at timestamptz
);
CREATE TABLE IF NOT EXISTS qualification_phases (
  run_id text NOT NULL REFERENCES qualification_runs(id) ON DELETE RESTRICT,
  name text NOT NULL,
  status text NOT NULL CHECK (status IN ('INTENT', 'SUBMITTED', 'COMPLETED', 'UNKNOWN')),
  intent_digest text NOT NULL,
  receipt jsonb,
  safe_reason text,
  created_at timestamptz NOT NULL,
  reconciliation_deadline timestamptz NOT NULL,
  submitted_at timestamptz,
  completed_at timestamptz,
  PRIMARY KEY (run_id, name)
);
CREATE TABLE IF NOT EXISTS qualification_allocations (
  id text PRIMARY KEY,
  run_id text NOT NULL REFERENCES qualification_runs(id) ON DELETE RESTRICT,
  kind text NOT NULL CHECK (kind IN ('POOL', 'STAGING')),
  identity text NOT NULL,
  intent_digest text NOT NULL,
  state text NOT NULL CHECK (state IN ('INTENT', 'RETAINED', 'UNKNOWN')),
  receipt jsonb,
  created_at timestamptz NOT NULL,
  UNIQUE (run_id, kind)
);

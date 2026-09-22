CREATE TABLE IF NOT EXISTS linux_import_runs (
  id text PRIMARY KEY,
  installation_id text NOT NULL REFERENCES installations(id) ON DELETE RESTRICT,
  idempotency_key text NOT NULL,
  normalized_payload text NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE', 'COMPLETED', 'UNKNOWN')),
  plan jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  completed_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS linux_import_runs_installation_stage
  ON linux_import_runs(installation_id, (plan->>'stageId'));
CREATE UNIQUE INDEX IF NOT EXISTS linux_import_runs_installation_idempotency
  ON linux_import_runs(installation_id, idempotency_key);
CREATE TABLE IF NOT EXISTS linux_import_phases (
  run_id text NOT NULL REFERENCES linux_import_runs(id) ON DELETE RESTRICT,
  name text NOT NULL CHECK (name IN ('UPLOAD', 'IMPORT', 'TEMPLATE', 'CLONE', 'STAMP', 'START', 'STOP', 'DESTROY_CLONE', 'DESTROY_TEMPLATE')),
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
ALTER TABLE linux_import_phases ADD COLUMN IF NOT EXISTS reconciliation_deadline timestamptz;
UPDATE linux_import_phases SET reconciliation_deadline = created_at + interval '15 minutes' WHERE reconciliation_deadline IS NULL;
ALTER TABLE linux_import_phases ALTER COLUMN reconciliation_deadline SET NOT NULL;
CREATE TABLE IF NOT EXISTS linux_import_allocations (
  id text PRIMARY KEY,
  run_id text NOT NULL REFERENCES linux_import_runs(id) ON DELETE RESTRICT,
  kind text NOT NULL CHECK (kind IN ('STAGING', 'TEMPLATE_DISK', 'CLONE_DISK')),
  identity text NOT NULL,
  intent_digest text NOT NULL,
  state text NOT NULL CHECK (state IN ('RESERVED', 'RETAINED', 'DESTROYED', 'UNKNOWN')),
  created_at timestamptz NOT NULL,
  UNIQUE (run_id, kind),
  UNIQUE (identity)
);

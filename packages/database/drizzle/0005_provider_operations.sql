ALTER TABLE operations ADD COLUMN IF NOT EXISTS snapshot jsonb;
ALTER TABLE operations ADD COLUMN IF NOT EXISTS task_handle jsonb;
ALTER TABLE operations ADD COLUMN IF NOT EXISTS safe_reason text;
ALTER TABLE operations ADD COLUMN IF NOT EXISTS submitted_at timestamptz;
ALTER TABLE operations ADD COLUMN IF NOT EXISTS reconciliation_deadline timestamptz;
ALTER TABLE operations DROP CONSTRAINT IF EXISTS operations_status_check;
ALTER TABLE operations ADD CONSTRAINT operations_status_check CHECK (status IN ('INTENT', 'SUBMITTED', 'COMPLETED', 'UNKNOWN'));
UPDATE operations
SET status = 'UNKNOWN', safe_reason = 'LEGACY_UNRESOLVED'
WHERE status IN ('INTENT', 'UNKNOWN') AND snapshot IS NULL;
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM operations
    WHERE status IN ('INTENT', 'SUBMITTED', 'UNKNOWN')
    GROUP BY resource_id
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'provider operation journal migration blocked: legacy unresolved operations duplicate a resource; resolve them before startup';
  END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS operations_one_unresolved_resource
ON operations(resource_id)
WHERE status IN ('INTENT', 'SUBMITTED', 'UNKNOWN');

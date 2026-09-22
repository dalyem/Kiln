ALTER TABLE resources ADD COLUMN IF NOT EXISTS provenance_required integer NOT NULL DEFAULT 0;
ALTER TABLE resources DROP CONSTRAINT IF EXISTS resources_type_check;
ALTER TABLE resources ADD CONSTRAINT resources_type_check CHECK (type IN ('development', 'execution', 'browser', 'gateway', 'network_probe', 'image_template'));

CREATE TABLE IF NOT EXISTS provenance_images (
  id text PRIMARY KEY,
  manifest jsonb NOT NULL,
  manifest_digest text NOT NULL UNIQUE,
  signer_fingerprint text NOT NULL,
  policy_digest text NOT NULL,
  imported_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS template_imports (
  resource_id text PRIMARY KEY REFERENCES resources(id) ON DELETE RESTRICT,
  image_id text NOT NULL REFERENCES provenance_images(id) ON DELETE RESTRICT,
  image_manifest_digest text NOT NULL,
  capabilities jsonb NOT NULL,
  nonce text NOT NULL UNIQUE,
  provider_id text NOT NULL,
  provider_kind text NOT NULL,
  provider_resource_id text NOT NULL,
  node text,
  pool text NOT NULL,
  attachments jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('READY', 'UNKNOWN', 'QUARANTINED', 'RETIRED')),
  created_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS provenance_images_name_version_arch
ON provenance_images ((manifest->>'name'), (manifest->>'version'), (manifest->>'arch'));
CREATE TABLE IF NOT EXISTS provisioning_plans (
  resource_id text PRIMARY KEY REFERENCES resources(id) ON DELETE RESTRICT,
  template_resource_id text NOT NULL REFERENCES template_imports(resource_id) ON DELETE RESTRICT,
  canonical_digest text NOT NULL UNIQUE,
  plan jsonb NOT NULL,
  created_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS provisioning_attachments (
  resource_id text NOT NULL REFERENCES provisioning_plans(resource_id) ON DELETE RESTRICT,
  attachment_id text NOT NULL,
  native_id text NOT NULL,
  attachment jsonb NOT NULL,
  PRIMARY KEY (resource_id, attachment_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS provenance_owned_attachment_native_id
ON provisioning_attachments(native_id)
WHERE (attachment->>'ownership') = 'OWNED_CHILD';
CREATE TABLE IF NOT EXISTS owned_attachment_identities (
  native_id text PRIMARY KEY,
  resource_id text NOT NULL REFERENCES resources(id) ON DELETE RESTRICT
);

# Kiln Python SDK

The Phase 1 SDK is a synchronous, typed REST client. It supports status,
resource, inventory, and fake-mode development creation calls. It does not run
workflows. Workflow primitives belong in a later SDK release once the workflow
runtime and its durable state contract exist.

Install for local development with `python -m pip install -e sdk/python`.
Keep the API token in trusted code. Do not place it in workflow output or a
browser client.

# Kiln MCP adapter

The MCP adapter uses the official TypeScript MCP SDK over stdio. It forwards a
small set of status and resource calls to Kiln Core. It does not contain
provider logic and it does not expose a tool that promises a real development
VM in Phase 1.

Set `KILN_URL` and `KILN_TOKEN` before starting it. The token remains in the
local MCP process and is sent only in the API bearer header. Logs go to stderr
because stdout is reserved for the MCP protocol.

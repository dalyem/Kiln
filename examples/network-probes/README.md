# Network probe profiles

Set `KILN_PROBE_PROFILES_FILE` to a private operator-managed copy of `profiles.json` before starting Kiln. Each profile lists fixed destinations and short timeouts. Requesters can select a profile ID, but cannot add a target, command, or script.

Profiles require all four gateway TLS files because plan and result routes use the server-authenticated enrollment listener. They are rejected at startup when that TLS configuration is incomplete.

The example addresses use documentation-only ranges. Replace them with endpoints you control. A probe result is diagnostic with `placement: "UNVERIFIED"`; it does not mark gateway canary evidence as passing or allow workloads.

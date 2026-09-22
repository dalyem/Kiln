# Kiln dashboard

The dashboard is a small App Router view for control-plane status and
Kiln-owned resource records. It reads `KILN_URL` and `KILN_TOKEN` only in a
server-only module. Neither variable has a `NEXT_PUBLIC_` prefix.

It uses native React and Tailwind components. Phase 1 has one static view with
no reusable interactive controls, so adding shadcn/ui would add dependencies
without solving a current problem.

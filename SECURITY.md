# Security Policy

Eye of Dharma is an independent community project, not affiliated with any government or agency.

## Reporting a vulnerability
Please open a private GitHub security advisory on this repository (Security → Report a vulnerability). Do not post exploit details in public issues.

## Implemented controls
- SSRF firewall on all server-side fetches (private, loopback, link-local, cloud-metadata and IPv4-in-IPv6 ranges blocked; DNS-rebinding checks; size/time caps).
- Zod validation on all request bodies; parameterised SQL only.
- Double-submit-cookie CSRF protection on state-changing requests.
- Evidence ledger protected by database triggers (no UPDATE/DELETE/REPLACE).
- XXE-safe feed parsing.

## Known limitations
- No user authentication or multi-user authorisation yet: run on localhost / a trusted network only.
- CORS currently reflects origin; tighten before any public deployment.

# sn-account-instance-hardening MCP server

MCP server exposing the hardening checks under `../scans` (level-1, level-2,
level-3, level-next, level-knowledge) as tools for browsing, searching, and
validating checks.

## Setup

```bash
npm install
npm run build
```

## Run

```bash
npm start
```

By default it reads checks from `../scans` relative to this directory. Override with:

```bash
SCANS_DIR=/path/to/scans npm start
```

The MITRE ATT&CK mapping data defaults to `data/attack-mappings.json`. Override with:

```bash
ATTACK_MAPPINGS_PATH=/path/to/attack-mappings.json npm start
```

## Tools

- `connect_instance` — authenticate to a client's ServiceNow instance via OAuth 2.0 Client Credentials and verify connectivity (see "Connecting to a client instance" below). Does not yet fetch live scan findings — connectivity verification only.
- `connection_status` — report whether there's an active, non-expired connection, and to which instance, without exposing credentials.
- `disconnect_instance` — discard the cached OAuth token.
- `list_levels` — list the scan suites and how many checks each contains.
- `list_checks` — list checks, filterable by level, category, suite, priority range, active status, keyword, ATT&CK tactic, or ATT&CK technique.
- `search_checks` — full-text search across name/description/resolution details.
- `get_check` — fetch a check's full JSON metadata + JS source + ATT&CK mapping by id.
- `get_attack_mapping` — fetch just the MITRE ATT&CK tactic/technique mapping, rationale, and ServiceNow best-practice guidance for a check. Use this to ground a remediation write-up instead of inferring the mapping yourself.
- `list_attack_techniques` — list every distinct ATT&CK technique referenced across all checks, with how many checks map to each.
- `validate_check` — validate check JSON against the repo's schema and lint JS source (syntax errors, missing `engine.finding` calls, leftover debug statements, `eval` usage). Works on inline `json`/`js`, or on an existing check via `id`/`level`.

## ATT&CK + best-practice enrichment

`data/attack-mappings.json` maps each check (`<level>/<id>`) to the MITRE ATT&CK
tactic(s)/technique(s) it most directly relates to, a one-line rationale, and a
ServiceNow-specific best-practice remediation note. These are practitioner-level,
best-effort mappings authored for this repo (see `_meta.methodology` in that file)
and should be reviewed by a security analyst before being presented as
authoritative in a client deliverable.

This enriches the **static check catalog**, not a specific client's live scan
results — it tells you what each check defends against and why it matters, not
which checks actually fired against a given instance. To turn it into a
client-specific remediation plan, cross-reference it with that client's actual
scan findings.

### Generating the standalone report

```bash
npm run report                 # writes reports/attack-remediation-report.html
npm run report -- /path/out.html
```

Renders a self-contained, filterable HTML reference (grouped by priority tier,
with ATT&CK tactic coverage and best-practice guidance per check) from
`scripts/report-template.html` + the current `scans/` + `data/attack-mappings.json`.
`reports/` is gitignored since it's a regenerable build artifact.

## Connecting to a client's ServiceNow instance

`connect_instance` takes `instanceUrl`, `clientId`, and (optionally) `clientSecret`,
performs an OAuth 2.0 Client Credentials grant against that instance's own
`/oauth_token.do` endpoint using a scoped integration user, and verifies the
token with a lightweight authenticated API call. The secret is never echoed
back, logged, or written to disk by this server, and the connection is held
in memory only for the life of the server process.

**Avoid passing `clientSecret` as a tool argument in an interactive chat** —
it will land in that conversation's transcript. Instead, supply it to the
server process via (checked in this order):

1. `SN_CLIENT_SECRET_FILE` — path to a mounted secret file, e.g. a volume
   populated by an External Secrets Operator / Vault Agent sidecar in
   Kubernetes. Takes precedence over the env var below.
2. `SN_CLIENT_SECRET` — the secret directly as an environment variable.
3. The `clientSecret` tool argument, as a last resort.

## Connecting from a client

Example `mcpServers` entry (e.g. for Claude Desktop/Code config):

```json
{
  "mcpServers": {
    "sn-account-instance-hardening": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-server/dist/index.js"]
    }
  }
}
```

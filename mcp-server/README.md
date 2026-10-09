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

## Tools

- `list_levels` — list the scan suites and how many checks each contains.
- `list_checks` — list checks, filterable by level, category, suite, priority range, active status, or keyword.
- `search_checks` — full-text search across name/description/resolution details.
- `get_check` — fetch a check's full JSON metadata + JS source by id.
- `validate_check` — validate check JSON against the repo's schema and lint JS source (syntax errors, missing `engine.finding` calls, leftover debug statements, `eval` usage). Works on inline `json`/`js`, or on an existing check via `id`/`level`.

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

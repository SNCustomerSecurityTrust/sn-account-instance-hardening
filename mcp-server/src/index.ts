#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ChecksRepo } from "./checks.js";
import { AttackMappingsRepo } from "./attackMappings.js";
import { checkMetaSchema } from "./schema.js";
import { lintCheckJs } from "./lint.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const scansDir = process.env.SCANS_DIR
  ? resolve(process.env.SCANS_DIR)
  : resolve(__dirname, "..", "..", "scans");

const attackMappingsPath = process.env.ATTACK_MAPPINGS_PATH
  ? resolve(process.env.ATTACK_MAPPINGS_PATH)
  : join(__dirname, "..", "data", "attack-mappings.json");

const attackMappings = new AttackMappingsRepo(attackMappingsPath);
const repo = new ChecksRepo(scansDir, attackMappings);

const server = new McpServer({
  name: "sn-account-instance-hardening-mcp",
  version: "1.0.0",
});

server.registerTool(
  "list_levels",
  {
    title: "List scan levels",
    description:
      "List the scan suites/levels in the sn-account-instance-hardening repo (level-1, level-2, level-3, level-next, level-knowledge) with how many checks each contains.",
    inputSchema: {},
  },
  async () => {
    const levels = repo.listLevels();
    return { content: [{ type: "text", text: JSON.stringify(levels, null, 2) }] };
  },
);

server.registerTool(
  "list_checks",
  {
    title: "List hardening checks",
    description:
      "List hardening scan checks, optionally filtered by level (e.g. 'level-1'), category, suite, priority range, active status, or a keyword that must appear in the name/description.",
    inputSchema: {
      level: z.string().optional().describe("Directory name, e.g. 'level-1', 'level-knowledge'"),
      category: z.string().optional(),
      suite: z.string().optional().describe("e.g. 'Level 1', 'Level Knowledge'"),
      minPriority: z.number().int().optional(),
      maxPriority: z.number().int().optional(),
      activeOnly: z.boolean().optional(),
      query: z.string().optional().describe("Keyword to match against name/short_description/description"),
      tactic: z.string().optional().describe("MITRE ATT&CK tactic name substring, e.g. 'Privilege Escalation'"),
      technique: z.string().optional().describe("MITRE ATT&CK technique id or name substring, e.g. 'T1078' or 'Valid Accounts'"),
    },
  },
  async (args) => {
    const results = repo.list(args);
    return {
      content: [{ type: "text", text: JSON.stringify({ count: results.length, checks: results }, null, 2) }],
    };
  },
);

server.registerTool(
  "search_checks",
  {
    title: "Search hardening checks",
    description:
      "Full-text search across a check's name, descriptions, category, and resolution details. Good for 'which checks mention MFA' style questions.",
    inputSchema: {
      query: z.string().min(1),
      limit: z.number().int().min(1).max(100).optional(),
    },
  },
  async ({ query, limit }) => {
    const results = repo.search(query, limit);
    return {
      content: [{ type: "text", text: JSON.stringify({ count: results.length, checks: results }, null, 2) }],
    };
  },
);

server.registerTool(
  "get_check",
  {
    title: "Get a hardening check",
    description:
      "Fetch a single check's full JSON metadata and JS source by id (the filename without extension, e.g. 'cstaces-1a-admin-users'). Pass level to disambiguate if the id exists in more than one level.",
    inputSchema: {
      id: z.string().min(1),
      level: z.string().optional(),
    },
  },
  async ({ id, level }) => {
    const matches = repo.get(id, level);
    if (matches.length === 0) {
      return {
        isError: true,
        content: [{ type: "text", text: `No check found with id '${id}'${level ? ` in ${level}` : ""}.` }],
      };
    }
    if (matches.length > 1) {
      return {
        content: [
          {
            type: "text",
            text: `Id '${id}' exists in multiple levels: ${matches.map((m) => m.level).join(", ")}. Pass 'level' to disambiguate.`,
          },
        ],
      };
    }
    const entry = matches[0];
    const js = repo.readJs(entry);
    const mapping = attackMappings.get(entry.level, entry.id);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { id: entry.id, level: entry.level, meta: entry.meta, js: js ?? null, attack_mapping: mapping ?? null },
            null,
            2,
          ),
        },
      ],
    };
  },
);

server.registerTool(
  "get_attack_mapping",
  {
    title: "Get MITRE ATT&CK mapping for a check",
    description:
      "Fetch the MITRE ATT&CK tactic/technique mapping, rationale, and ServiceNow best-practice guidance for a check by id. Use this to ground a client-facing remediation write-up instead of inferring the mapping yourself.",
    inputSchema: {
      id: z.string().min(1),
      level: z.string().optional(),
    },
  },
  async ({ id, level }) => {
    const matches = repo.get(id, level);
    if (matches.length === 0) {
      return {
        isError: true,
        content: [{ type: "text", text: `No check found with id '${id}'${level ? ` in ${level}` : ""}.` }],
      };
    }
    if (matches.length > 1 && !level) {
      return {
        content: [
          {
            type: "text",
            text: `Id '${id}' exists in multiple levels: ${matches.map((m) => m.level).join(", ")}. Pass 'level' to disambiguate.`,
          },
        ],
      };
    }
    const entry = matches[0];
    const mapping = attackMappings.get(entry.level, entry.id);
    if (!mapping) {
      return {
        content: [{ type: "text", text: `No ATT&CK mapping recorded yet for '${entry.level}/${entry.id}'.` }],
      };
    }
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ id: entry.id, level: entry.level, priority: entry.meta.priority, ...mapping }, null, 2),
        },
      ],
    };
  },
);

server.registerTool(
  "list_attack_techniques",
  {
    title: "List MITRE ATT&CK techniques covered by this repo's checks",
    description:
      "List every distinct ATT&CK technique referenced across all checks' mappings, with how many checks map to each. Useful for building ATT&CK coverage views or picking a technique to filter list_checks by.",
    inputSchema: {},
  },
  async () => {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { methodology: attackMappings.getMethodology(), techniques: attackMappings.listTechniques() },
            null,
            2,
          ),
        },
      ],
    };
  },
);

server.registerTool(
  "validate_check",
  {
    title: "Validate a hardening check",
    description:
      "Validate a check's JSON metadata against the repo's schema and lint its JS source for common issues (syntax errors, missing engine.finding calls, leftover debug statements). Pass either raw json/js, or an id+level to validate an existing file on disk.",
    inputSchema: {
      id: z.string().optional().describe("Existing check id to validate instead of inline json/js"),
      level: z.string().optional(),
      json: z.record(z.string(), z.unknown()).optional().describe("Inline check metadata to validate"),
      js: z.string().optional().describe("Inline JS source to lint"),
    },
  },
  async ({ id, level, json, js }) => {
    let metaToValidate: unknown = json;
    let jsToLint: string | undefined = js;

    if (id) {
      const matches = repo.get(id, level);
      if (matches.length === 0) {
        return {
          isError: true,
          content: [{ type: "text", text: `No check found with id '${id}'${level ? ` in ${level}` : ""}.` }],
        };
      }
      if (matches.length > 1 && !level) {
        return {
          content: [
            {
              type: "text",
              text: `Id '${id}' exists in multiple levels: ${matches.map((m) => m.level).join(", ")}. Pass 'level' to disambiguate.`,
            },
          ],
        };
      }
      const entry = matches[0];
      metaToValidate = metaToValidate ?? entry.meta;
      jsToLint = jsToLint ?? repo.readJs(entry) ?? undefined;
    }

    const report: { jsonErrors: string[]; jsIssues: ReturnType<typeof lintCheckJs> } = {
      jsonErrors: [],
      jsIssues: [],
    };

    if (metaToValidate !== undefined) {
      const parsed = checkMetaSchema.safeParse(metaToValidate);
      if (!parsed.success) {
        report.jsonErrors = parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`);
      }
    }

    if (jsToLint !== undefined) {
      report.jsIssues = lintCheckJs(jsToLint);
    }

    const ok =
      report.jsonErrors.length === 0 && report.jsIssues.every((i) => i.level !== "error");

    return {
      content: [{ type: "text", text: JSON.stringify({ ok, ...report }, null, 2) }],
    };
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);

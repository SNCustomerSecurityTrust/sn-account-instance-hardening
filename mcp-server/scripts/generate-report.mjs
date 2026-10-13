#!/usr/bin/env node
// Merges scans/ metadata with data/attack-mappings.json and renders the
// standalone ATT&CK remediation reference report (scripts/report-template.html).
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "..");
const scansDir = resolve(root, "..", "scans");
const mappingsPath = join(root, "data", "attack-mappings.json");
const templatePath = join(root, "scripts", "report-template.html");
const outPath = process.argv[2] ? resolve(process.argv[2]) : join(root, "reports", "attack-remediation-report.html");

const { _meta, ...mappings } = JSON.parse(readFileSync(mappingsPath, "utf-8"));

const levels = readdirSync(scansDir, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name);

const entries = [];
for (const level of levels) {
  const levelDir = join(scansDir, level);
  const files = readdirSync(levelDir).filter((f) => f.endsWith(".json"));
  for (const file of files) {
    const id = file.replace(/\.json$/, "");
    const meta = JSON.parse(readFileSync(join(levelDir, file), "utf-8"));
    const mapping = mappings[`${level}/${id}`] ?? null;
    entries.push({ id, level, meta, mapping });
  }
}
entries.sort((a, b) => a.meta.priority - b.meta.priority || a.id.localeCompare(b.id));

const missing = entries.filter((e) => !e.mapping);
if (missing.length) {
  console.warn(`Warning: ${missing.length} check(s) have no ATT&CK mapping:`, missing.map((e) => `${e.level}/${e.id}`));
}

const dataJson = JSON.stringify(entries).replace(/<\/script>/g, "<\\/script>");
const template = readFileSync(templatePath, "utf-8");
const rendered = template.replace("__REPORT_DATA__", dataJson);

writeFileSync(outPath, rendered);
console.log(`Wrote ${entries.length} checks (${missing.length} missing mapping) to ${outPath}`);

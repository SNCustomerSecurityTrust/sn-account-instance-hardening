import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, basename, extname } from "node:path";
import type { CheckEntry, CheckSummary } from "./types.js";

export class ChecksRepo {
  private entries: CheckEntry[] = [];
  private loadedAt = 0;

  constructor(private readonly scansDir: string) {}

  private load(): void {
    const levels = readdirSync(this.scansDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name);

    const entries: CheckEntry[] = [];

    for (const level of levels) {
      const levelDir = join(this.scansDir, level);
      const files = readdirSync(levelDir).filter((f) => extname(f) === ".json");

      for (const jsonFile of files) {
        const id = basename(jsonFile, ".json");
        const jsonPath = join(levelDir, jsonFile);
        const jsPath = join(levelDir, `${id}.js`);

        let meta;
        try {
          meta = JSON.parse(readFileSync(jsonPath, "utf-8"));
        } catch {
          continue;
        }

        let hasJs = true;
        try {
          statSync(jsPath);
        } catch {
          hasJs = false;
        }

        entries.push({
          id,
          level,
          jsonPath,
          jsPath: hasJs ? jsPath : "",
          meta,
        });
      }
    }

    this.entries = entries;
    this.loadedAt = Date.now();
  }

  private ensureLoaded(): void {
    // Reload if never loaded, or stale beyond 10s (allows editing checks without restarting the server).
    if (this.entries.length === 0 || Date.now() - this.loadedAt > 10_000) {
      this.load();
    }
  }

  listLevels(): { level: string; count: number }[] {
    this.ensureLoaded();
    const counts = new Map<string, number>();
    for (const e of this.entries) {
      counts.set(e.level, (counts.get(e.level) ?? 0) + 1);
    }
    return [...counts.entries()].map(([level, count]) => ({ level, count }));
  }

  list(filter: {
    level?: string;
    category?: string;
    suite?: string;
    minPriority?: number;
    maxPriority?: number;
    activeOnly?: boolean;
    query?: string;
  }): CheckSummary[] {
    this.ensureLoaded();
    const q = filter.query?.toLowerCase();

    return this.entries
      .filter((e) => !filter.level || e.level === filter.level)
      .filter((e) => !filter.category || e.meta.category === filter.category)
      .filter((e) => !filter.suite || e.meta.suite === filter.suite)
      .filter((e) => filter.minPriority === undefined || e.meta.priority >= filter.minPriority)
      .filter((e) => filter.maxPriority === undefined || e.meta.priority <= filter.maxPriority)
      .filter((e) => !filter.activeOnly || e.meta.active)
      .filter((e) => {
        if (!q) return true;
        const haystack = `${e.meta.name} ${e.meta.short_description} ${e.meta.description}`.toLowerCase();
        return haystack.includes(q);
      })
      .map((e) => this.toSummary(e))
      .sort((a, b) => a.id.localeCompare(b.id));
  }

  get(id: string, level?: string): CheckEntry[] {
    this.ensureLoaded();
    return this.entries.filter((e) => e.id === id && (!level || e.level === level));
  }

  search(query: string, limit = 20): CheckSummary[] {
    this.ensureLoaded();
    const q = query.toLowerCase();
    return this.entries
      .filter((e) => {
        const haystack = [
          e.meta.name,
          e.meta.short_description,
          e.meta.description,
          e.meta.resolution_details,
          e.meta.category,
        ]
          .join(" ")
          .toLowerCase();
        return haystack.includes(q);
      })
      .slice(0, limit)
      .map((e) => this.toSummary(e));
  }

  readJs(entry: CheckEntry): string | null {
    if (!entry.jsPath) return null;
    return readFileSync(entry.jsPath, "utf-8");
  }

  private toSummary(e: CheckEntry): CheckSummary {
    return {
      id: e.id,
      level: e.level,
      name: e.meta.name,
      short_description: e.meta.short_description,
      category: e.meta.category,
      priority: e.meta.priority,
      suite: e.meta.suite,
      active: e.meta.active,
      sys_id: e.meta.sys_id,
    };
  }
}

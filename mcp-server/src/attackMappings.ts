import { readFileSync } from "node:fs";
import type { AttackMapping } from "./types.js";

export class AttackMappingsRepo {
  private mappings: Record<string, AttackMapping> = {};
  private methodology = "";

  constructor(private readonly dataPath: string) {
    this.load();
  }

  private load(): void {
    const raw = JSON.parse(readFileSync(this.dataPath, "utf-8"));
    const { _meta, ...rest } = raw;
    this.methodology = _meta?.methodology ?? "";
    this.mappings = rest;
  }

  get(level: string, id: string): AttackMapping | undefined {
    return this.mappings[`${level}/${id}`];
  }

  getMethodology(): string {
    return this.methodology;
  }

  all(): { key: string; mapping: AttackMapping }[] {
    return Object.entries(this.mappings).map(([key, mapping]) => ({ key, mapping }));
  }

  listTechniques(): { id: string; name: string; checkCount: number }[] {
    const byId = new Map<string, { id: string; name: string; checkCount: number }>();
    for (const { mapping } of this.all()) {
      for (const t of mapping.techniques) {
        const existing = byId.get(t.id);
        if (existing) {
          existing.checkCount += 1;
        } else {
          byId.set(t.id, { id: t.id, name: t.name, checkCount: 1 });
        }
      }
    }
    return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
  }
}

export interface CheckMeta {
  active: boolean;
  category: string;
  description: string;
  documentation_url: string;
  finding_type: string;
  name: string;
  priority: number;
  resolution_details: string;
  run_condition: string;
  score_max: number;
  score_min: number;
  score_scale: number;
  short_description: string;
  sys_id: string;
  sys_class_name: string;
  suite: string;
}

export interface CheckEntry {
  id: string;
  level: string;
  jsonPath: string;
  jsPath: string;
  meta: CheckMeta;
}

export interface CheckSummary {
  id: string;
  level: string;
  name: string;
  short_description: string;
  category: string;
  priority: number;
  suite: string;
  active: boolean;
  sys_id: string;
  tactics?: string[];
  techniques?: AttackTechnique[];
}

export interface AttackTechnique {
  id: string;
  name: string;
}

export interface AttackMapping {
  tactics: string[];
  techniques: AttackTechnique[];
  rationale: string;
  best_practice: string;
}

import { z } from "zod";

export const checkMetaSchema = z.object({
  active: z.boolean(),
  category: z.string().min(1),
  description: z.string().min(1),
  documentation_url: z.string().min(1),
  finding_type: z.string().min(1),
  name: z.string().min(1),
  priority: z.number().int().min(1).max(5),
  resolution_details: z.string().min(1),
  run_condition: z.string(),
  score_max: z.number(),
  score_min: z.number(),
  score_scale: z.number(),
  short_description: z.string().min(1).max(160),
  sys_id: z.string().regex(/^[0-9a-f]{32}$/i, "sys_id must be a 32-character hex string"),
  sys_class_name: z.string().min(1),
  suite: z.string().min(1),
});

export type CheckMetaInput = z.infer<typeof checkMetaSchema>;

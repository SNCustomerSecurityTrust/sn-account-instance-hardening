import vm from "node:vm";

export interface LintIssue {
  level: "error" | "warning";
  message: string;
}

export function lintCheckJs(source: string): LintIssue[] {
  const issues: LintIssue[] = [];

  try {
    // Compiling (not running) the script catches syntax errors without executing
    // ServiceNow-only globals like GlideRecord/engine that don't exist in this process.
    new vm.Script(source, { filename: "check.js" });
  } catch (err) {
    issues.push({
      level: "error",
      message: `Syntax error: ${err instanceof Error ? err.message : String(err)}`,
    });
    return issues;
  }

  if (!/\(function\s*\(engine\)\s*\{[\s\S]*\}\)\(engine\)\s*;?\s*$/.test(source.trim())) {
    issues.push({
      level: "warning",
      message:
        "Script does not follow the standard '(function(engine) { ... })(engine);' wrapper used by other checks in this repo.",
    });
  }

  if (!/engine\.finding\.(setValue|increment|setCurrentSource)/.test(source)) {
    issues.push({
      level: "warning",
      message: "Script never calls engine.finding.setValue/increment/setCurrentSource — it may not record findings.",
    });
  }

  if (!/engine\.finding\.increment\s*\(/.test(source)) {
    issues.push({
      level: "warning",
      message: "Script never calls engine.finding.increment() — findings may not be counted.",
    });
  }

  if (/\bconsole\.(log|debug)\s*\(/.test(source)) {
    issues.push({ level: "warning", message: "Contains console.log/debug — remove debug statements before shipping." });
  }

  if (/\bgs\.(info|debug|print)\s*\(/.test(source)) {
    issues.push({
      level: "warning",
      message: "Contains gs.info/debug/print calls — these look like leftover debug statements (other checks keep them commented out).",
    });
  }

  if (/\beval\s*\(/.test(source)) {
    issues.push({ level: "warning", message: "Uses eval() — avoid dynamic code execution in scan scripts." });
  }

  return issues;
}

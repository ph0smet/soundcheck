import { OUTCOME_LABEL, type ReportModel } from "./model";

function cell(value: string) {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function code(value: string) {
  return value.includes("`") ? `\`\` ${value} \`\`` : `\`${value}\``;
}

export function renderMarkdown(report: ReportModel): string {
  const lines: string[] = [];
  const push = (...items: string[]) => lines.push(...items);

  push(`# ${report.title}`, "");
  push(`**Overall: ${report.statusLabel}.** ${report.statusSummary}`, "");
  push(
    `| | |`,
    `|---|---|`,
    `| Source | ${cell(report.source)} |`,
    `| Gateway | ${report.gateway} |`,
    `| Assurance profile | ${code(report.profile)} |`,
    `| Generated | ${report.generatedAt} |`,
    "",
  );

  push("## Summary", "", "| Metric | Count |", "|---|---:|");
  for (const [label, value] of report.stats) push(`| ${label} | ${value} |`);
  push("");

  push("## Checks", "");
  for (const check of report.checks) {
    push(`- **${check.label}**${check.parameters ? ` (${check.parameters})` : ""}: ${check.description}`);
    for (const statement of check.statement) push(`  ${code(statement)}`);
  }
  push("");

  if (report.matrix.length > 0) {
    push("## Results", "");
    push(`| File | ${report.checks.map((check) => cell(check.label)).join(" | ")} |`);
    push(`|---|${report.checks.map(() => "---").join("|")}|`);
    for (const row of report.matrix) {
      push(`| ${cell(row.path)} | ${row.outcomes.map((outcome) => OUTCOME_LABEL[outcome]).join(" | ")} |`);
    }
    push("");

    push("## Details by file", "");
    for (const section of report.sections) {
      push(`### ${section.file.path}`, "");
      push(`Worst outcome: **${OUTCOME_LABEL[section.worst]}**${section.assurance ? ` · Assurance: ${section.assurance}` : ""}`, "");
      if (section.shared) {
        const exit = section.shared.exitCode !== null ? ` (exit ${section.shared.exitCode})` : "";
        push(`- **${OUTCOME_LABEL[section.shared.outcome]}** all ${section.findings.length} checks${exit}: ${section.shared.summary}`);
        push(`  - Reproduce: ${code(section.findings[0].command)}`);
      } else {
        for (const finding of section.findings) {
          const exit = finding.exitCode !== null ? ` (exit ${finding.exitCode})` : "";
          push(`- **${OUTCOME_LABEL[finding.outcome]}** ${finding.check.label}${exit}: ${finding.summary}`);
          if (finding.outcome !== "proved") push(`  - Reproduce: ${code(finding.command)}`);
        }
      }
      if (section.assuranceFindings.length > 0) {
        push("", "Assurance findings:", "");
        for (const item of section.assuranceFindings) push(`- ${item}`);
      }
      push("");
    }
  } else {
    push("## Results", "", "No Kong configuration was found in the upload.", "");
  }

  if (report.skipped.length > 0) {
    push("## Skipped files", "", "| File | Reason |", "|---|---|");
    for (const item of report.skipped) push(`| ${cell(item.path)} | ${cell(item.detail)} |`);
    push("");
  }

  if (report.contract) {
    push("## Frozen contract", "", "```yaml", report.contract.trimEnd(), "```", "");
  }

  push("## Scope of these results", "");
  for (const note of report.scope) push(`- ${note}`);
  push("");

  return lines.join("\n");
}

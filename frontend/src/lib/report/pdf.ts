import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage, type RGB } from "pdf-lib";

import type { CellOutcome } from "../audit";
import { OUTCOME_LABEL, type ReportModel } from "./model";

const PAGE: [number, number] = [595.28, 841.89];
const MARGIN = { x: 50, top: 56, bottom: 60 };
const WIDTH = PAGE[0] - MARGIN.x * 2;

const INK = rgb(0.05, 0.06, 0.09);
const MUTED = rgb(0.36, 0.4, 0.45);
const FAINT = rgb(0.55, 0.58, 0.63);
const LINE = rgb(0.86, 0.88, 0.91);
const WASH = rgb(0.965, 0.97, 0.98);

const TONES: Record<CellOutcome | "pass" | "review" | "fail", RGB> = {
  proved: rgb(0.04, 0.48, 0.32),
  violated: rgb(0.77, 0.18, 0.1),
  vacuous: rgb(0.6, 0.36, 0),
  inconsistent: rgb(0.66, 0.14, 0.44),
  unknown: rgb(0.31, 0.31, 0.81),
  error: rgb(0.45, 0.45, 0.5),
  pending: FAINT,
  pass: rgb(0.04, 0.48, 0.32),
  review: rgb(0.6, 0.36, 0),
  fail: rgb(0.77, 0.18, 0.1),
};

// Standard PDF fonts only encode WinAnsi; logic symbols get ASCII spellings.
const REPLACEMENTS: Record<string, string> = {
  "∀": "forall", "∃": "exists", "∧": "and", "∨": "or", "⇒": "=>", "→": "->", "←": "<-",
  "∈": "in", "∉": "not in", "⊒": ">=", "≥": ">=", "≤": "<=", "≠": "!=", "↵": "Enter",
  "✓": "ok", "✗": "x", "\t": "  ",
};
const WIN_ANSI_EXTRA = "€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ";

function safe(text: string): string {
  let out = "";
  for (const char of text.replace(/\r/g, "")) {
    const code = char.codePointAt(0)!;
    if ((code >= 32 && code <= 126) || (code >= 160 && code <= 255) || char === "\n" || WIN_ANSI_EXTRA.includes(char)) {
      out += char;
    } else {
      out += REPLACEMENTS[char] ?? "?";
    }
  }
  return out;
}

interface Fonts {
  regular: PDFFont;
  bold: PDFFont;
  mono: PDFFont;
}

interface TextStyle {
  font?: keyof Fonts;
  size?: number;
  color?: RGB;
  indent?: number;
  width?: number;
  leading?: number;
}

interface Cell {
  text: string;
  color?: RGB;
  font?: keyof Fonts;
}

class Writer {
  page!: PDFPage;
  y = 0;

  constructor(
    readonly doc: PDFDocument,
    readonly fonts: Fonts,
  ) {
    this.addPage();
  }

  addPage() {
    this.page = this.doc.addPage(PAGE);
    this.y = PAGE[1] - MARGIN.top;
  }

  ensure(height: number) {
    if (this.y - height < MARGIN.bottom) this.addPage();
  }

  wrap(text: string, font: PDFFont, size: number, width: number): string[] {
    const lines: string[] = [];
    for (const paragraph of safe(text).split("\n")) {
      let line = "";
      for (const word of paragraph.split(/ +/)) {
        const candidate = line ? `${line} ${word}` : word;
        if (font.widthOfTextAtSize(candidate, size) <= width) {
          line = candidate;
          continue;
        }
        if (line) lines.push(line);
        line = word;
        while (font.widthOfTextAtSize(line, size) > width && line.length > 1) {
          let cut = line.length - 1;
          while (cut > 1 && font.widthOfTextAtSize(line.slice(0, cut), size) > width) cut--;
          lines.push(line.slice(0, cut));
          line = line.slice(cut);
        }
      }
      lines.push(line);
    }
    return lines;
  }

  text(text: string, style: TextStyle = {}) {
    const font = this.fonts[style.font ?? "regular"];
    const size = style.size ?? 9.5;
    const indent = style.indent ?? 0;
    const leading = style.leading ?? size * 1.45;
    for (const line of this.wrap(text, font, size, (style.width ?? WIDTH) - indent)) {
      this.ensure(leading);
      this.y -= leading;
      this.page.drawText(line, { x: MARGIN.x + indent, y: this.y + (leading - size) / 2, size, font, color: style.color ?? INK });
    }
  }

  gap(amount: number) {
    this.y -= amount;
  }

  rule() {
    this.ensure(10);
    this.y -= 6;
    this.page.drawLine({ start: { x: MARGIN.x, y: this.y }, end: { x: MARGIN.x + WIDTH, y: this.y }, thickness: 0.6, color: LINE });
    this.y -= 6;
  }

  heading(text: string, level: 1 | 2 | 3) {
    const size = level === 1 ? 20 : level === 2 ? 13 : 10.5;
    // Keep room for the heading plus its first lines so it never ends a page alone.
    this.ensure(level === 1 ? size * 3 : 80);
    this.gap(level === 1 ? 0 : level === 2 ? 14 : 8);
    this.text(text, { font: "bold", size, leading: size * 1.35 });
    this.gap(level === 3 ? 2 : 6);
  }

  table(columns: { header: string; width: number }[], rows: Cell[][], size = 8) {
    const pad = 5;
    const leading = size * 1.35;
    const headerCells: Cell[] = columns.map((column) => ({ text: column.header }));
    const drawRow = (cells: Cell[], header: boolean) => {
      const wrapped = cells.map((cell, i) =>
        this.wrap(cell.text, this.fonts[cell.font ?? (header ? "bold" : "regular")], size, columns[i].width - pad * 2),
      );
      const height = Math.max(...wrapped.map((lines) => lines.length)) * leading + pad * 2;
      if (this.y - height < MARGIN.bottom) {
        this.addPage();
        if (!header) drawRow(headerCells, true);
      }
      if (header) {
        this.page.drawRectangle({ x: MARGIN.x, y: this.y - height, width: WIDTH, height, color: WASH });
      }
      let x = MARGIN.x;
      wrapped.forEach((lines, i) => {
        const cell = cells[i];
        const font = this.fonts[cell.font ?? (header ? "bold" : "regular")];
        lines.forEach((line, n) => {
          this.page.drawText(line, {
            x: x + pad,
            y: this.y - pad - (n + 1) * leading + (leading - size) / 2 + 1,
            size,
            font,
            color: cell.color ?? (header ? MUTED : INK),
          });
        });
        x += columns[i].width;
      });
      this.y -= height;
      this.page.drawLine({ start: { x: MARGIN.x, y: this.y }, end: { x: MARGIN.x + WIDTH, y: this.y }, thickness: 0.5, color: LINE });
    };
    drawRow(headerCells, true);
    for (const row of rows) drawRow(row, false);
  }
}

function outcomeCell(outcome: CellOutcome): Cell {
  return { text: OUTCOME_LABEL[outcome], color: TONES[outcome], font: "bold" };
}

export async function renderPdf(report: ReportModel): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  doc.setTitle(`${report.title}: ${report.source}`);
  doc.setSubject("Soundcheck verification results");
  doc.setProducer("Soundcheck");
  doc.setCreator("Soundcheck web");
  const fonts: Fonts = {
    regular: await doc.embedFont(StandardFonts.Helvetica),
    bold: await doc.embedFont(StandardFonts.HelveticaBold),
    mono: await doc.embedFont(StandardFonts.Courier),
  };
  const w = new Writer(doc, fonts);

  // Title block
  w.text("SOUNDCHECK", { font: "bold", size: 8, color: FAINT });
  w.heading(report.title, 1);
  w.text(`${report.source} · ${report.gateway} · ${report.profile}`, { color: MUTED });
  w.text(`Generated ${report.generatedAt}`, { color: FAINT, size: 8.5 });
  w.gap(14);

  // Overall status band
  const band = 46;
  w.ensure(band + 10);
  const tone = TONES[report.status];
  w.page.drawRectangle({ x: MARGIN.x, y: w.y - band, width: WIDTH, height: band, color: WASH });
  w.page.drawRectangle({ x: MARGIN.x, y: w.y - band, width: 4, height: band, color: tone });
  w.page.drawText(safe(report.statusLabel.toUpperCase()), { x: MARGIN.x + 16, y: w.y - 22, size: 15, font: fonts.bold, color: tone });
  w.page.drawText(safe(report.statusSummary), { x: MARGIN.x + 16, y: w.y - 37, size: 8.5, font: fonts.regular, color: MUTED });
  w.y -= band + 14;

  // Stats grid, five per row
  const perRow = 5;
  const boxW = WIDTH / perRow;
  const boxH = 38;
  for (let i = 0; i < report.stats.length; i += perRow) {
    w.ensure(boxH);
    report.stats.slice(i, i + perRow).forEach(([label, value], j) => {
      const x = MARGIN.x + j * boxW;
      w.page.drawRectangle({ x: x + 1, y: w.y - boxH, width: boxW - 2, height: boxH - 2, borderColor: LINE, borderWidth: 0.6 });
      w.page.drawText(safe(value), { x: x + 8, y: w.y - 19, size: 13, font: fonts.bold, color: INK });
      w.page.drawText(safe(label), { x: x + 8, y: w.y - 31, size: 7, font: fonts.regular, color: MUTED });
    });
    w.y -= boxH + 2;
  }

  // Checks
  w.heading("Checks", 2);
  for (const check of report.checks) {
    w.text(`${check.label}${check.parameters ? ` (${check.parameters})` : ""}`, { font: "bold", size: 9.5 });
    w.text(check.description, { color: MUTED, size: 9, indent: 10 });
    for (const statement of check.statement) w.text(statement, { font: "mono", size: 7.5, indent: 10, color: MUTED });
    w.gap(4);
  }

  // Results matrix
  w.heading("Results", 2);
  if (report.matrix.length === 0) {
    w.text("No Kong configuration was found in the upload.", { color: MUTED });
  } else {
    const fileWidth = Math.min(190, WIDTH * 0.38);
    const checkWidth = (WIDTH - fileWidth) / report.checks.length;
    w.table(
      [{ header: "File", width: fileWidth }, ...report.checks.map((check) => ({ header: check.label, width: checkWidth }))],
      report.matrix.map((row) => [{ text: row.path, font: "mono" as const }, ...row.outcomes.map(outcomeCell)]),
      7.5,
    );
  }

  // Per-file details
  if (report.sections.length > 0) {
    w.heading("Details by file", 2);
    for (const section of report.sections) {
      w.heading(section.file.path, 3);
      w.text(`Worst outcome: ${OUTCOME_LABEL[section.worst]}${section.assurance ? ` · Assurance: ${section.assurance}` : ""}`, {
        size: 8.5,
        color: MUTED,
      });
      w.gap(3);
      const line = (outcome: CellOutcome, title: string, exitCode: number | null, summary: string, command: string | null) => {
        w.ensure(28);
        const label = OUTCOME_LABEL[outcome];
        const labelWidth = fonts.bold.widthOfTextAtSize(label, 8.5);
        w.y -= 13;
        w.page.drawText(label, { x: MARGIN.x, y: w.y + 2, size: 8.5, font: fonts.bold, color: TONES[outcome] });
        w.page.drawText(safe(`${title}${exitCode !== null ? `  (exit ${exitCode})` : ""}`), {
          x: MARGIN.x + Math.max(labelWidth, 70) + 8,
          y: w.y + 2,
          size: 8.5,
          font: fonts.bold,
          color: INK,
        });
        w.text(summary, { size: 8.5, color: MUTED, indent: 78 });
        if (command) w.text(`$ ${command}`, { font: "mono", size: 7, indent: 78, color: FAINT });
      };
      if (section.shared) {
        const { outcome, exitCode, summary } = section.shared;
        line(outcome, `All ${section.findings.length} checks`, exitCode, summary, section.findings[0].command);
      } else {
        for (const finding of section.findings) {
          line(finding.outcome, finding.check.label, finding.exitCode, finding.summary, finding.outcome !== "proved" ? finding.command : null);
        }
      }
      if (section.assuranceFindings.length > 0) {
        w.gap(3);
        w.text("Assurance findings", { font: "bold", size: 8, color: MUTED });
        for (const item of section.assuranceFindings) w.text(`- ${item}`, { size: 8, color: MUTED, indent: 8 });
      }
      w.rule();
    }
  }

  if (report.skipped.length > 0) {
    w.heading("Skipped files", 2);
    w.table(
      [{ header: "File", width: WIDTH * 0.45 }, { header: "Reason", width: WIDTH * 0.55 }],
      report.skipped.map((item) => [{ text: item.path, font: "mono" as const }, { text: item.detail, color: MUTED }]),
    );
  }

  if (report.contract) {
    w.heading("Frozen contract", 2);
    w.text(report.contract.trimEnd(), { font: "mono", size: 8, color: MUTED });
  }

  w.heading("Scope of these results", 2);
  for (const note of report.scope) w.text(`- ${note.replace(/`/g, "")}`, { size: 8.5, color: MUTED, indent: 4 });

  // Footer on every page
  const pages = doc.getPages();
  pages.forEach((page, i) => {
    const footer = safe(`Soundcheck audit · ${report.source}`);
    page.drawText(footer, { x: MARGIN.x, y: 30, size: 7, font: fonts.regular, color: FAINT });
    const number = `${i + 1} / ${pages.length}`;
    page.drawText(number, { x: MARGIN.x + WIDTH - fonts.regular.widthOfTextAtSize(number, 7), y: 30, size: 7, font: fonts.regular, color: FAINT });
  });

  return doc.save();
}

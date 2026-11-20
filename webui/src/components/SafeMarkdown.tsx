import React, { useState } from "react";
import { Check, Copy } from "lucide-react";

const CTRL_AND_WS_RE = /[\u0000-\u0020\u007f]+/g;
const ALLOWED_SCHEME_RE = /^(https?:|mailto:)/i;

/**
 * Strictly sanitize Markdown link targets.
 * Strips ASCII whitespace and control characters before scheme checks, blocks
 * protocol-relative URLs (`//...`), and allows ONLY `https:`, `http:`, and `mailto:`.
 */
export function sanitizeHref(raw: string): string | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const normalized = trimmed.replace(CTRL_AND_WS_RE, "");
  if (!normalized) return null;
  if (normalized.startsWith("//") || normalized.startsWith("\\\\")) {
    return null;
  }
  if (!ALLOWED_SCHEME_RE.test(normalized)) {
    return null;
  }
  const low = normalized.toLowerCase();
  if (low.startsWith("mailto:")) {
    const addr = normalized.slice("mailto:".length);
    if (!addr || !addr.includes("@") || /[\r\n<>]/.test(addr)) {
      return null;
    }
    return normalized;
  }
  try {
    const parsed = new URL(normalized);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return null;
    }
    return parsed.href;
  } catch {
    return null;
  }
}

function CodeBlock({ lang, code }: { lang: string; code: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    void navigator.clipboard?.writeText(code).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div className="my-2 rounded-lg border border-slate-800 bg-slate-950/90 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1 border-b border-slate-800/80 bg-slate-900/70 text-[11px] text-slate-400">
        <span className="font-mono">{lang || "text"}</span>
        <button
          type="button"
          onClick={handleCopy}
          className="inline-flex items-center gap-1 text-slate-400 hover:text-slate-100 cursor-pointer"
        >
          {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          <span>{copied ? "已复制" : "复制"}</span>
        </button>
      </div>
      <pre className="p-3 overflow-x-auto text-xs leading-relaxed font-mono text-slate-200 whitespace-pre">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function renderInline(text: string, keyPrefix: string): React.ReactNode[] {
  const nodes: React.ReactNode[] = [];
  let idx = 0;
  let tokenCounter = 0;

  const inlineRe =
    /(`[^`\n]+`)|(\[([^\]\n]+)\]\(([^)\n]+)\))|(\*\*([^*\n]+)\*\*)|(~~([^~\n]+)~~)|(\*([^*\n]+)\*)/g;

  let match: RegExpExecArray | null;
  while ((match = inlineRe.exec(text)) !== null) {
    if (match.index > idx) {
      nodes.push(text.slice(idx, match.index));
    }
    const k = `${keyPrefix}-${tokenCounter++}`;
    if (match[1]) {
      nodes.push(
        <code
          key={k}
          className="px-1.5 py-0.5 rounded bg-slate-800/90 text-sky-300 font-mono text-[0.85em]"
        >
          {match[1].slice(1, -1)}
        </code>,
      );
    } else if (match[2]) {
      const label = match[3] || "";
      const hrefRaw = match[4] || "";
      const safeHref = sanitizeHref(hrefRaw);
      if (safeHref) {
        nodes.push(
          <a
            key={k}
            href={safeHref}
            target="_blank"
            rel="noopener noreferrer nofollow"
            className="text-sky-400 hover:text-sky-300 underline decoration-sky-500/40 underline-offset-2 break-all"
          >
            {label}
          </a>,
        );
      } else {
        nodes.push(
          <span key={k} className="text-slate-400">
            [{label}]
          </span>,
        );
      }
    } else if (match[5]) {
      nodes.push(
        <strong key={k} className="font-semibold text-slate-50">
          {renderInline(match[6], `${k}-b`)}
        </strong>,
      );
    } else if (match[7]) {
      nodes.push(
        <del key={k} className="line-through text-slate-400">
          {renderInline(match[8], `${k}-s`)}
        </del>,
      );
    } else if (match[9]) {
      nodes.push(
        <em key={k} className="italic text-slate-200">
          {renderInline(match[10], `${k}-i`)}
        </em>,
      );
    }
    idx = match.index + match[0].length;
  }

  if (idx < text.length) {
    nodes.push(text.slice(idx));
  }
  return nodes;
}

function isTableSeparator(line: string): boolean {
  const s = line.trim();
  if (!s.includes("|")) return false;
  const cells = s.replace(/^\||\|$/g, "").split("|");
  return cells.length >= 2 && cells.every((c) => /^:?-{3,}:?$/.test(c.trim()));
}

function splitTableCells(line: string): string[] {
  return line
    .trim()
    .replace(/^\||\|$/g, "")
    .split("|")
    .map((c) => c.trim());
}

const FENCE_OPEN_RE = /^(`{3,})([^\n]*)$/;
const HEADING_RE = /^(#{1,6})\s+(\S.*)$/;
const HEADING_STOP_RE = /^#{1,6}\s+\S/;
const HR_RE = /^\s*(?:[-*_]\s*){3,}$/;
const UL_ITEM_RE = /^\s*[-*+]\s+/;
const OL_ITEM_RE = /^\s*\d+\.\s+/;

export type MarkdownBlock =
  | { type: "code"; lang: string; code: string }
  | { type: "hr" }
  | { type: "heading"; level: number; text: string }
  | { type: "blockquote"; lines: string[] }
  | { type: "table"; headers: string[]; rows: string[][] }
  | { type: "ul"; items: string[] }
  | { type: "ol"; items: string[] }
  | { type: "paragraph"; lines: string[] };

/**
 * Pure, linear-time, strictly monotonic Markdown block parser.
 * Guarantees `i` advances by at least 1 on every outer loop iteration.
 */
export function parseMarkdownBlocks(content: string): MarkdownBlock[] {
  const lines = (content || "").replace(/\r\n/g, "\n").split("\n");
  const parsed: MarkdownBlock[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block (supports 3+ backticks & arbitrary language/info strings)
    const fenceMatch = line.match(FENCE_OPEN_RE);
    if (fenceMatch) {
      const fenceLen = fenceMatch[1].length;
      const lang = (fenceMatch[2] || "").trim();
      const closeFenceRe = new RegExp(`^\`{${fenceLen},}\\s*$`);
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !closeFenceRe.test(lines[i])) {
        codeLines.push(lines[i]);
        i++;
      }
      if (i < lines.length) i++;
      parsed.push({ type: "code", lang, code: codeLines.join("\n") });
      continue;
    }

    // Blank line
    if (!line.trim()) {
      i++;
      continue;
    }

    // Horizontal rule
    if (HR_RE.test(line)) {
      parsed.push({ type: "hr" });
      i++;
      continue;
    }

    // Headings (strictly isomorphic with paragraph stop condition)
    const hMatch = line.match(HEADING_RE);
    if (hMatch) {
      parsed.push({ type: "heading", level: hMatch[1].length, text: hMatch[2] });
      i++;
      continue;
    }

    // Blockquote
    if (line.startsWith(">")) {
      const qLines: string[] = [];
      while (i < lines.length && lines[i].startsWith(">")) {
        qLines.push(lines[i].replace(/^>\s?/, ""));
        i++;
      }
      parsed.push({ type: "blockquote", lines: qLines });
      continue;
    }

    // Table
    if (line.includes("|") && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
      const headers = splitTableCells(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) {
        rows.push(splitTableCells(lines[i]));
        i++;
      }
      parsed.push({ type: "table", headers, rows });
      continue;
    }

    // Unordered list
    if (UL_ITEM_RE.test(line)) {
      const items: string[] = [];
      while (i < lines.length && UL_ITEM_RE.test(lines[i])) {
        items.push(lines[i].replace(UL_ITEM_RE, ""));
        i++;
      }
      parsed.push({ type: "ul", items });
      continue;
    }

    // Ordered list
    if (OL_ITEM_RE.test(line)) {
      const items: string[] = [];
      while (i < lines.length && OL_ITEM_RE.test(lines[i])) {
        items.push(lines[i].replace(OL_ITEM_RE, ""));
        i++;
      }
      parsed.push({ type: "ol", items });
      continue;
    }

    // Paragraph (coalesce contiguous plain lines)
    const paraLines: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() &&
      !FENCE_OPEN_RE.test(lines[i]) &&
      !HEADING_STOP_RE.test(lines[i]) &&
      !lines[i].startsWith(">") &&
      !UL_ITEM_RE.test(lines[i]) &&
      !OL_ITEM_RE.test(lines[i]) &&
      !HR_RE.test(lines[i]) &&
      !(lines[i].includes("|") && i + 1 < lines.length && isTableSeparator(lines[i + 1]))
    ) {
      paraLines.push(lines[i]);
      i++;
    }
    // Monotonic progress guard: guarantee `i` strictly increases even on unexpected inputs
    if (paraLines.length === 0) {
      paraLines.push(lines[i]);
      i++;
    }
    parsed.push({ type: "paragraph", lines: paraLines });
  }

  return parsed;
}

export interface SafeMarkdownProps {
  content: string;
  className?: string;
}

/**
 * Zero-dependency pure React AST Markdown renderer.
 * Never uses dangerouslySetInnerHTML, innerHTML, eval, or new Function;
 * raw HTML tags are rendered strictly as escaped plain text.
 */
export function SafeMarkdown({ content, className = "" }: SafeMarkdownProps) {
  const parsedBlocks = parseMarkdownBlocks(content);
  const blocks: React.ReactNode[] = parsedBlocks.map((block, bIdx) => {
    const key = `b-${bIdx}`;
    switch (block.type) {
      case "code":
        return <CodeBlock key={key} lang={block.lang} code={block.code} />;
      case "hr":
        return <hr key={key} className="my-3 border-slate-800" />;
      case "heading": {
        const cls =
          block.level === 1
            ? "text-base font-bold text-slate-50 mt-3 mb-1.5"
            : block.level === 2
              ? "text-sm font-semibold text-slate-100 mt-2.5 mb-1"
              : "text-xs font-semibold text-slate-200 mt-2 mb-1";
        return (
          <div key={key} className={cls}>
            {renderInline(block.text, `h-${bIdx}`)}
          </div>
        );
      }
      case "blockquote":
        return (
          <blockquote
            key={key}
            className="my-2 border-l-2 border-sky-500/50 pl-3 text-slate-300 space-y-1"
          >
            {block.lines.map((ql, qi) => (
              <p key={`${key}-${qi}`}>{renderInline(ql, `${key}-${qi}`)}</p>
            ))}
          </blockquote>
        );
      case "table":
        return (
          <div key={key} className="my-2 overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full text-xs text-left border-collapse">
              <thead className="bg-slate-900/80 text-slate-300">
                <tr>
                  {block.headers.map((hc, ci) => (
                    <th key={`${key}-h-${ci}`} className="px-2.5 py-1.5 border-b border-slate-800 font-medium">
                      {renderInline(hc, `${key}-h-${ci}`)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {block.rows.map((row, ri) => (
                  <tr key={`${key}-r-${ri}`} className="border-b border-slate-800/60 last:border-b-0">
                    {row.map((cell, ci) => (
                      <td key={`${key}-c-${ri}-${ci}`} className="px-2.5 py-1.5 text-slate-200">
                        {renderInline(cell, `${key}-c-${ri}-${ci}`)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      case "ul":
        return (
          <ul key={key} className="my-1.5 list-disc pl-5 space-y-1">
            {block.items.map((it, li) => (
              <li key={`${key}-${li}`}>{renderInline(it, `${key}-${li}`)}</li>
            ))}
          </ul>
        );
      case "ol":
        return (
          <ol key={key} className="my-1.5 list-decimal pl-5 space-y-1">
            {block.items.map((it, li) => (
              <li key={`${key}-${li}`}>{renderInline(it, `${key}-${li}`)}</li>
            ))}
          </ol>
        );
      case "paragraph":
        return (
          <p key={key} className="my-1.5 leading-relaxed whitespace-pre-wrap break-words">
            {block.lines.map((pl, pi) => (
              <React.Fragment key={`${key}-${pi}`}>
                {pi > 0 && <br />}
                {renderInline(pl, `${key}-${pi}`)}
              </React.Fragment>
            ))}
          </p>
        );
    }
  });

  return <div className={`text-sm text-slate-100 ${className}`}>{blocks}</div>;
}

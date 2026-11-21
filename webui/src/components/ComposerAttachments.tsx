import {
  type ClipboardEvent as ReactClipboardEvent,
  type DragEvent as ReactDragEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  AlertCircle,
  AtSign,
  Check,
  Download,
  FileArchive,
  FileAudio,
  FileCode,
  FileText,
  FileVideo,
  Image as ImageIcon,
  Loader2,
  Search,
  Upload,
  X,
  ZoomIn,
} from "lucide-react";
import { fetchFileTree, uploadChatAttachment } from "../api";
import type { ChatAttachmentItem, FileTreeNode } from "../types";

export const MAX_ATTACHMENTS_PER_MSG = 6;
export const MAX_CONTEXT_FILES_PER_MSG = 10;

export const FILE_INPUT_ACCEPT = [
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/gif",
  ".png",
  ".jpg",
  ".jpeg",
  ".webp",
  ".gif",
  ".pdf",
  ".txt",
  ".md",
  ".csv",
  ".json",
  ".yaml",
  ".yml",
  ".xml",
  ".toml",
  ".log",
  ".docx",
  ".xlsx",
  ".py",
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".go",
  ".rs",
  ".sh",
  ".sql",
  ".html",
  ".css",
  ".c",
  ".cpp",
  ".h",
  ".java",
  ".diff",
  ".patch",
  ".ini",
  ".conf",
  ".mp3",
  ".wav",
  ".ogg",
  ".m4a",
  ".flac",
  ".mp4",
  ".webm",
  ".mov",
  ".zip",
  ".gz",
  ".tgz",
].join(",");

export const SUPPORTED_FORMATS_TOOLTIP =
  "支持图片(PNG/JPG/WebP/GIF ≤15MB)、PDF/文档(≤20MB)、代码(≤5MB)、音视频(MP3/WAV/MP4/WebM/MOV ≤25MB)及压缩包(ZIP/TGZ ≤25MB)；支持拖拽与 Ctrl+V 粘贴截屏";

export interface PendingAttachment {
  localId: string;
  name: string;
  size: number;
  kind: string;
  status: "uploading" | "ready" | "error";
  error?: string;
  localPreviewUrl?: string;
  attachment?: ChatAttachmentItem;
}

export function formatBytesCompact(n?: number): string {
  if (typeof n !== "number" || !Number.isFinite(n) || n <= 0) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function guessKindFromName(name: string, mime = ""): string {
  const low = name.toLowerCase();
  const m = mime.toLowerCase();
  if (low.endsWith(".png") || low.endsWith(".jpg") || low.endsWith(".jpeg") || low.endsWith(".webp") || low.endsWith(".gif") || m.startsWith("image/")) {
    return "image";
  }
  if (low.endsWith(".pdf") || m === "application/pdf") return "pdf";
  if (low.endsWith(".mp3") || low.endsWith(".wav") || low.endsWith(".ogg") || low.endsWith(".m4a") || low.endsWith(".flac") || m.startsWith("audio/")) {
    return "audio";
  }
  if (low.endsWith(".mp4") || low.endsWith(".webm") || low.endsWith(".mov") || m.startsWith("video/")) {
    return "video";
  }
  if (low.endsWith(".zip") || low.endsWith(".gz") || low.endsWith(".tgz")) return "archive";
  if (
    /\.(py|ts|tsx|js|jsx|go|rs|sh|sql|html|css|c|cpp|h|java|diff|patch|ini|conf)$/.test(low)
  ) {
    return "code";
  }
  return "document";
}

function kindChipStyle(kind: string): {
  bg: string;
  border: string;
  text: string;
  badge: string;
  Icon: typeof FileText;
} {
  switch (kind) {
    case "image":
      return {
        bg: "bg-sky-500/12",
        border: "border-sky-500/35",
        text: "text-sky-200",
        badge: "IMG",
        Icon: ImageIcon,
      };
    case "pdf":
      return {
        bg: "bg-rose-500/12",
        border: "border-rose-500/35",
        text: "text-rose-200",
        badge: "PDF",
        Icon: FileText,
      };
    case "audio":
      return {
        bg: "bg-violet-500/12",
        border: "border-violet-500/35",
        text: "text-violet-200",
        badge: "音频",
        Icon: FileAudio,
      };
    case "video":
      return {
        bg: "bg-indigo-500/12",
        border: "border-indigo-500/35",
        text: "text-indigo-200",
        badge: "视频",
        Icon: FileVideo,
      };
    case "code":
      return {
        bg: "bg-cyan-500/12",
        border: "border-cyan-500/35",
        text: "text-cyan-200",
        badge: "代码",
        Icon: FileCode,
      };
    case "archive":
      return {
        bg: "bg-amber-500/12",
        border: "border-amber-500/35",
        text: "text-amber-200",
        badge: "压缩包",
        Icon: FileArchive,
      };
    default:
      return {
        bg: "bg-emerald-500/12",
        border: "border-emerald-500/35",
        text: "text-emerald-200",
        badge: "文档",
        Icon: FileText,
      };
  }
}

export interface UseAttachmentComposerOptions {
  disabled?: boolean;
  onAuthError?: (err: unknown) => boolean;
}

export function useAttachmentComposer({
  disabled = false,
  onAuthError,
}: UseAttachmentComposerOptions = {}) {
  const [pendingAttachments, setPendingAttachments] = useState<PendingAttachment[]>([]);
  const [contextFiles, setContextFiles] = useState<string[]>([]);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const mountedRef = useRef(true);
  const dragDepthRef = useRef(0);
  const pendingRef = useRef<PendingAttachment[]>([]);
  pendingRef.current = pendingAttachments;
  const onAuthErrorRef = useRef(onAuthError);
  onAuthErrorRef.current = onAuthError;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      for (const item of pendingRef.current) {
        if (item.localPreviewUrl) {
          URL.revokeObjectURL(item.localPreviewUrl);
        }
      }
    };
  }, []);

  const addFiles = useCallback(
    (incoming: FileList | File[]) => {
      if (disabled) return;
      const list = Array.from(incoming || []);
      if (list.length === 0) return;

      const currentCount = pendingRef.current.filter((p) => p.status !== "error").length;
      const available = MAX_ATTACHMENTS_PER_MSG - currentCount;
      if (available <= 0) {
        setUploadError(`单条消息最多附加 ${MAX_ATTACHMENTS_PER_MSG} 个文件`);
        return;
      }

      const accepted: File[] = [];
      for (const f of list) {
        const lower = (f.name || "").toLowerCase();
        if (lower.endsWith(".svg") || lower.endsWith(".svgz") || f.type === "image/svg+xml") {
          setUploadError("禁止上传 SVG 文件（防范脚本注入风险），请转为 PNG/JPG/WebP");
          continue;
        }
        if (accepted.length >= available) {
          setUploadError(`已达单条消息附件上限（最多 ${MAX_ATTACHMENTS_PER_MSG} 个），多余文件已忽略`);
          break;
        }
        accepted.push(f);
      }

      if (accepted.length === 0) return;
      setUploadError(null);

      for (const file of accepted) {
        const localId = `loc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const fname = file.name || (file.type.startsWith("image/") ? `screenshot_${Date.now()}.png` : "attachment");
        const kind = guessKindFromName(fname, file.type);
        const localPreviewUrl =
          kind === "image" && file.type.startsWith("image/") && file.type !== "image/svg+xml"
            ? URL.createObjectURL(file)
            : undefined;

        const entry: PendingAttachment = {
          localId,
          name: fname,
          size: file.size,
          kind,
          status: "uploading",
          localPreviewUrl,
        };
        setPendingAttachments((prev) => [...prev, entry]);

        // Ensure pasted blobs without filename carry an extension
        const uploadFile =
          file.name && file.name.includes(".")
            ? file
            : new File([file], fname, { type: file.type || "application/octet-stream" });

        void uploadChatAttachment(uploadFile)
          .then((res) => {
            if (!mountedRef.current) return;
            setPendingAttachments((prev) =>
              prev.map((item) =>
                item.localId === localId
                  ? {
                      ...item,
                      status: "ready",
                      attachment: res.attachment,
                      name: res.attachment.name,
                      size: res.attachment.size ?? item.size,
                      kind: res.attachment.kind || item.kind,
                    }
                  : item,
              ),
            );
          })
          .catch((err) => {
            if (!mountedRef.current) return;
            if (onAuthErrorRef.current?.(err)) return;
            const msg = err instanceof Error ? err.message : "上传失败";
            setUploadError(`${fname}：${msg}`);
            setPendingAttachments((prev) =>
              prev.map((item) =>
                item.localId === localId ? { ...item, status: "error", error: msg } : item,
              ),
            );
          });
      }
    },
    [disabled],
  );

  const removeAttachment = useCallback((localId: string) => {
    setPendingAttachments((prev) => {
      const target = prev.find((i) => i.localId === localId);
      if (target?.localPreviewUrl) {
        URL.revokeObjectURL(target.localPreviewUrl);
      }
      return prev.filter((i) => i.localId !== localId);
    });
  }, []);

  const addContextFile = useCallback(
    (relPath: string) => {
      if (disabled) return;
      const clean = relPath.trim().replace(/^@+/, "");
      if (!clean) return;
      setContextFiles((prev) => {
        if (prev.includes(clean)) return prev;
        if (prev.length >= MAX_CONTEXT_FILES_PER_MSG) {
          setUploadError(`单条消息最多引用 ${MAX_CONTEXT_FILES_PER_MSG} 个工作区文件`);
          return prev;
        }
        return [...prev, clean];
      });
    },
    [disabled],
  );

  const removeContextFile = useCallback((relPath: string) => {
    setContextFiles((prev) => prev.filter((p) => p !== relPath));
  }, []);

  const clearAll = useCallback(() => {
    setPendingAttachments((prev) => {
      for (const item of prev) {
        if (item.localPreviewUrl) {
          URL.revokeObjectURL(item.localPreviewUrl);
        }
      }
      return [];
    });
    setContextFiles([]);
    setUploadError(null);
  }, []);

  const handlePaste = useCallback(
    (e: ReactClipboardEvent<HTMLElement>) => {
      if (disabled) return;
      const dt = e.clipboardData;
      if (!dt) return;
      const files: File[] = [];
      if (dt.items && dt.items.length > 0) {
        for (let i = 0; i < dt.items.length; i += 1) {
          const item = dt.items[i];
          if (item.kind === "file") {
            const f = item.getAsFile();
            if (f) files.push(f);
          }
        }
      } else if (dt.files && dt.files.length > 0) {
        for (let i = 0; i < dt.files.length; i += 1) {
          files.push(dt.files[i]);
        }
      }
      if (files.length > 0) {
        // Only prevent default if clipboard has no plain text (so pasting rich content or pure screenshot works seamlessly)
        const text = dt.getData("text/plain");
        if (!text) {
          e.preventDefault();
        }
        addFiles(files);
      }
    },
    [addFiles, disabled],
  );

  const hasFilesInDrag = (e: ReactDragEvent<HTMLElement>): boolean => {
    const types = e.dataTransfer?.types;
    if (!types) return false;
    for (let i = 0; i < types.length; i += 1) {
      if (types[i] === "Files") return true;
    }
    return false;
  };

  const dragHandlers = useMemo(
    () => ({
      onDragEnter: (e: ReactDragEvent<HTMLElement>) => {
        if (disabled || !hasFilesInDrag(e)) return;
        e.preventDefault();
        dragDepthRef.current += 1;
        setIsDragging(true);
      },
      onDragOver: (e: ReactDragEvent<HTMLElement>) => {
        if (disabled || !hasFilesInDrag(e)) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = "copy";
      },
      onDragLeave: (_e: ReactDragEvent<HTMLElement>) => {
        if (disabled) return;
        if (dragDepthRef.current > 0) {
          dragDepthRef.current -= 1;
        }
        if (dragDepthRef.current <= 0) {
          dragDepthRef.current = 0;
          setIsDragging(false);
        }
      },
      onDrop: (e: ReactDragEvent<HTMLElement>) => {
        if (disabled) return;
        dragDepthRef.current = 0;
        setIsDragging(false);
        if (!hasFilesInDrag(e)) return;
        e.preventDefault();
        if (e.dataTransfer?.files && e.dataTransfer.files.length > 0) {
          addFiles(e.dataTransfer.files);
        }
      },
    }),
    [addFiles, disabled],
  );

  const isUploading = pendingAttachments.some((p) => p.status === "uploading");
  const readyAttachments = useMemo(
    () =>
      pendingAttachments
        .filter((p): p is PendingAttachment & { attachment: ChatAttachmentItem } => p.status === "ready" && Boolean(p.attachment))
        .map((p) => p.attachment),
    [pendingAttachments],
  );
  const readyAttachmentIds = useMemo(
    () => readyAttachments.map((a) => a.id),
    [readyAttachments],
  );

  return {
    pendingAttachments,
    contextFiles,
    uploadError,
    setUploadError,
    isDragging,
    isUploading,
    readyAttachments,
    readyAttachmentIds,
    addFiles,
    removeAttachment,
    addContextFile,
    removeContextFile,
    clearAll,
    handlePaste,
    dragHandlers,
  };
}

// ---------------------------------------------------------------------------
// Composer Attachment & Context File Tray
// ---------------------------------------------------------------------------

export interface ComposerAttachmentTrayProps {
  attachments: PendingAttachment[];
  contextFiles: string[];
  uploadError?: string | null;
  onDismissError?: () => void;
  onRemoveAttachment: (localId: string) => void;
  onRemoveContextFile: (relPath: string) => void;
  onPreviewImage: (src: string, name: string) => void;
}

export function ComposerAttachmentTray({
  attachments,
  contextFiles,
  uploadError,
  onDismissError,
  onRemoveAttachment,
  onRemoveContextFile,
  onPreviewImage,
}: ComposerAttachmentTrayProps) {
  if (attachments.length === 0 && contextFiles.length === 0 && !uploadError) {
    return null;
  }

  return (
    <div className="mb-2 space-y-1.5">
      {uploadError && (
        <div className="flex items-center justify-between gap-2 rounded-lg border border-rose-500/35 bg-rose-500/10 px-2.5 py-1 text-[11px] text-rose-200">
          <span className="inline-flex items-center gap-1.5 min-w-0 truncate">
            <AlertCircle className="w-3.5 h-3.5 shrink-0 text-rose-300" />
            <span className="truncate">{uploadError}</span>
          </span>
          {onDismissError && (
            <button
              type="button"
              onClick={onDismissError}
              className="text-rose-300 hover:text-rose-100 shrink-0 cursor-pointer"
              aria-label="关闭上传提示"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      )}

      {(attachments.length > 0 || contextFiles.length > 0) && (
        <div className="flex flex-wrap items-center gap-1.5 max-h-36 overflow-y-auto pr-0.5">
          {attachments.map((item) => {
            const isImg = item.kind === "image";
            const previewSrc = item.attachment?.preview_url || item.localPreviewUrl || "";
            if (isImg && previewSrc && item.status !== "error") {
              return (
                <div
                  key={item.localId}
                  className="group relative h-14 w-14 rounded-xl border border-slate-700/80 bg-slate-950 overflow-hidden shrink-0"
                  title={`${item.name} (${formatBytesCompact(item.size)})`}
                >
                  <button
                    type="button"
                    onClick={() => onPreviewImage(previewSrc, item.name)}
                    className="block h-full w-full cursor-pointer"
                  >
                    <img
                      src={previewSrc}
                      alt={item.name}
                      className="h-full w-full object-cover"
                    />
                    {item.status === "ready" && (
                      <span className="absolute inset-0 bg-slate-950/45 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                        <ZoomIn className="w-4 h-4 text-white" />
                      </span>
                    )}
                  </button>
                  {item.status === "uploading" && (
                    <div className="absolute inset-0 bg-slate-950/65 flex items-center justify-center">
                      <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
                    </div>
                  )}
                  <button
                    type="button"
                    onClick={() => onRemoveAttachment(item.localId)}
                    title="移除附件"
                    aria-label={`移除 ${item.name}`}
                    className="absolute top-0.5 right-0.5 h-4 w-4 rounded-full bg-slate-950/85 hover:bg-rose-600 text-slate-200 hover:text-white inline-flex items-center justify-center cursor-pointer"
                  >
                    <X className="w-2.5 h-2.5" />
                  </button>
                </div>
              );
            }

            const style = kindChipStyle(item.kind);
            const Icon = style.Icon;
            const isErr = item.status === "error";
            return (
              <div
                key={item.localId}
                title={isErr ? item.error || "上传失败" : `${item.name} (${formatBytesCompact(item.size)})`}
                className={`inline-flex items-center gap-1.5 max-w-[220px] rounded-lg border px-2 py-1 text-[11px] ${
                  isErr
                    ? "border-rose-500/45 bg-rose-500/12 text-rose-200"
                    : `${style.border} ${style.bg} ${style.text}`
                }`}
              >
                {item.status === "uploading" ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0 text-sky-300" />
                ) : isErr ? (
                  <AlertCircle className="w-3.5 h-3.5 shrink-0 text-rose-300" />
                ) : (
                  <Icon className="w-3.5 h-3.5 shrink-0" />
                )}
                <span className="truncate font-medium">{item.name}</span>
                {item.size > 0 && !isErr && (
                  <span className="text-[10px] opacity-70 shrink-0 font-mono">
                    {formatBytesCompact(item.size)}
                  </span>
                )}
                {isErr && <span className="text-[10px] text-rose-300 shrink-0">失败</span>}
                <button
                  type="button"
                  onClick={() => onRemoveAttachment(item.localId)}
                  aria-label={`移除 ${item.name}`}
                  className="ml-0.5 rounded hover:bg-slate-800/80 p-0.5 cursor-pointer shrink-0"
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
            );
          })}

          {contextFiles.map((relPath) => (
            <div
              key={relPath}
              title={`工作区文件引用: @${relPath}`}
              className="inline-flex items-center gap-1 max-w-[240px] rounded-lg border border-cyan-500/35 bg-cyan-500/10 px-2 py-1 text-[11px] text-cyan-200 font-mono"
            >
              <AtSign className="w-3 h-3 shrink-0 text-cyan-400" />
              <span className="truncate">{relPath}</span>
              <button
                type="button"
                onClick={() => onRemoveContextFile(relPath)}
                aria-label={`移除引用 ${relPath}`}
                className="ml-0.5 rounded hover:bg-slate-800/80 p-0.5 cursor-pointer shrink-0"
              >
                <X className="w-3 h-3" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Workspace `@` File Picker Popover (Antigravity Desktop Style)
// ---------------------------------------------------------------------------

const fileListCache = new Map<string, { ts: number; files: string[] }>();
const FILE_CACHE_TTL_MS = 60_000;

function flattenFileNodes(nodes: FileTreeNode[], acc: string[]): void {
  for (const n of nodes) {
    if (n.type === "file" && n.path) {
      acc.push(n.path);
    }
    if (n.children && n.children.length > 0) {
      flattenFileNodes(n.children, acc);
    }
  }
}

function collectExpandableDirs(nodes: FileTreeNode[], out: string[], maxCount = 6): void {
  for (const n of nodes) {
    if (out.length >= maxCount) return;
    if (n.type === "dir" && n.has_children && (!n.children || n.children.length === 0)) {
      out.push(n.path);
    } else if (n.children && n.children.length > 0) {
      collectExpandableDirs(n.children, out, maxCount);
    }
  }
}

function fuzzyScore(path: string, query: string): number {
  if (!query) return 1;
  const q = query.toLowerCase();
  const p = path.toLowerCase();
  const base = p.split("/").pop() || p;
  if (base === q) return 1000;
  if (base.startsWith(q)) return 500 - base.length;
  const idxBase = base.indexOf(q);
  if (idxBase >= 0) return 300 - idxBase;
  const idxPath = p.indexOf(q);
  if (idxPath >= 0) return 150 - idxPath;
  // Subsequence match
  let qi = 0;
  for (let i = 0; i < p.length && qi < q.length; i += 1) {
    if (p[i] === q[qi]) qi += 1;
  }
  return qi === q.length ? 50 - Math.min(40, p.length / 4) : 0;
}

export interface WorkspaceFilePickerPopoverProps {
  open: boolean;
  projectId: string | undefined;
  query: string;
  showSearchInput?: boolean;
  selectedFiles: string[];
  activeIndex: number;
  onActiveIndexChange: (idx: number) => void;
  onQueryChange?: (q: string) => void;
  onSelect: (relPath: string) => void;
  onClose: () => void;
  onVisibleFilesChange?: (files: string[]) => void;
}

export function WorkspaceFilePickerPopover({
  open,
  projectId,
  query,
  showSearchInput = false,
  selectedFiles,
  activeIndex,
  onActiveIndexChange,
  onQueryChange,
  onSelect,
  onClose,
  onVisibleFilesChange,
}: WorkspaceFilePickerPopoverProps) {
  const [allFiles, setAllFiles] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open || !projectId) return;
    if (showSearchInput) {
      window.setTimeout(() => searchInputRef.current?.focus(), 20);
    }

    const cached = fileListCache.get(projectId);
    if (cached && Date.now() - cached.ts < FILE_CACHE_TTL_MS) {
      setAllFiles(cached.files);
      setError(null);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    void fetchFileTree({ project_id: projectId, depth: 2 })
      .then(async (res) => {
        if (cancelled) return;
        const collected: string[] = [];
        flattenFileNodes(res.entries || [], collected);

        // Lazily expand up to 4 deep sub-directories (e.g. webui/src, studio) for rich @ completion
        const subdirs: string[] = [];
        collectExpandableDirs(res.entries || [], subdirs, 4);
        if (subdirs.length > 0) {
          const extras = await Promise.all(
            subdirs.map((d) =>
              fetchFileTree({ project_id: projectId, dir: d, depth: 2 }).catch(() => null),
            ),
          );
          if (cancelled) return;
          for (const ex of extras) {
            if (ex?.entries) {
              flattenFileNodes(ex.entries, collected);
            }
          }
        }

        const uniqueSorted = Array.from(new Set(collected)).sort((a, b) => a.localeCompare(b));
        fileListCache.set(projectId, { ts: Date.now(), files: uniqueSorted });
        setAllFiles(uniqueSorted);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "加载工作区文件失败");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [open, projectId, showSearchInput]);

  const filteredFiles = useMemo(() => {
    const q = query.trim();
    if (!q) return allFiles.slice(0, 40);
    return allFiles
      .map((p) => ({ p, score: fuzzyScore(p, q) }))
      .filter((x) => x.score > 0)
      .sort((a, b) => b.score - a.score || a.p.localeCompare(b.p))
      .slice(0, 40)
      .map((x) => x.p);
  }, [allFiles, query]);

  useEffect(() => {
    onVisibleFilesChange?.(filteredFiles);
  }, [filteredFiles, onVisibleFilesChange]);

  useEffect(() => {
    if (!open) return;
    const container = listRef.current;
    if (!container) return;
    const activeEl = container.querySelector<HTMLElement>(`[data-picker-idx="${activeIndex}"]`);
    if (activeEl) {
      activeEl.scrollIntoView({ block: "nearest" });
    }
  }, [activeIndex, open]);

  if (!open) return null;

  return (
    <div
      role="listbox"
      aria-label="引用工作区文件"
      className="absolute bottom-full left-0 mb-1.5 z-40 w-full sm:w-[26rem] max-w-[calc(100vw-2rem)] rounded-xl border border-slate-700/90 bg-slate-900/98 shadow-2xl backdrop-blur-md overflow-hidden"
    >
      <div className="px-2.5 py-1.5 border-b border-slate-800 flex items-center justify-between gap-2 bg-slate-950/60">
        <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-cyan-300">
          <AtSign className="w-3.5 h-3.5" />
          <span>引用工作区文件</span>
          {projectId && (
            <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] font-mono text-slate-300">
              {projectId}
            </span>
          )}
        </span>
        <button
          type="button"
          onClick={onClose}
          className="text-slate-400 hover:text-slate-200 cursor-pointer"
          aria-label="关闭文件选择器"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      {showSearchInput && (
        <div className="px-2 py-1.5 border-b border-slate-800/80 bg-slate-950/40">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-1/2 -translate-y-1/2" />
            <input
              ref={searchInputRef}
              type="text"
              value={query}
              onChange={(e) => {
                onQueryChange?.(e.target.value);
                onActiveIndexChange(0);
              }}
              onKeyDown={(e) => {
                if (e.key === "Escape") {
                  e.preventDefault();
                  onClose();
                } else if (e.key === "ArrowDown") {
                  e.preventDefault();
                  if (filteredFiles.length > 0) {
                    onActiveIndexChange((activeIndex + 1) % filteredFiles.length);
                  }
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  if (filteredFiles.length > 0) {
                    onActiveIndexChange(
                      (activeIndex - 1 + filteredFiles.length) % filteredFiles.length,
                    );
                  }
                } else if (e.key === "Enter" || e.key === "Tab") {
                  e.preventDefault();
                  const hit = filteredFiles[activeIndex];
                  if (hit) onSelect(hit);
                }
              }}
              placeholder="输入文件名或路径模糊搜索…"
              className="w-full h-7 pl-7 pr-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>
      )}

      <div ref={listRef} className="max-h-56 overflow-y-auto py-1">
        {!projectId ? (
          <div className="px-3 py-4 text-center text-xs text-slate-400">
            请先在左侧选择一个工作区项目
          </div>
        ) : loading ? (
          <div className="px-3 py-4 flex items-center justify-center gap-2 text-xs text-slate-400">
            <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
            <span>正在索引项目文件…</span>
          </div>
        ) : error ? (
          <div className="px-3 py-3 text-xs text-rose-300">{error}</div>
        ) : filteredFiles.length === 0 ? (
          <div className="px-3 py-4 text-center text-xs text-slate-500">
            未找到匹配的工作区文件{query ? `（"${query}"）` : ""}
          </div>
        ) : (
          filteredFiles.map((filePath, idx) => {
            const parts = filePath.split("/");
            const basename = parts.pop() || filePath;
            const dir = parts.join("/");
            const isSelected = selectedFiles.includes(filePath);
            const isActive = idx === activeIndex;
            return (
              <button
                key={filePath}
                type="button"
                role="option"
                aria-selected={isSelected}
                data-picker-idx={idx}
                onMouseEnter={() => onActiveIndexChange(idx)}
                onMouseDown={(e) => {
                  e.preventDefault();
                  onSelect(filePath);
                }}
                className={`w-full px-2.5 py-1.5 text-left flex items-center gap-2 text-xs transition-colors cursor-pointer ${
                  isActive
                    ? "bg-cyan-500/15 text-slate-100"
                    : "text-slate-300 hover:bg-slate-800/70"
                }`}
              >
                <FileCode className="w-3.5 h-3.5 shrink-0 text-cyan-400" />
                <span className="min-w-0 flex-1 flex items-baseline gap-1.5 overflow-hidden">
                  <span className="font-mono font-medium text-slate-100 truncate shrink-0 max-w-[55%]">
                    {basename}
                  </span>
                  {dir && (
                    <span className="font-mono text-[10px] text-slate-500 truncate">{dir}</span>
                  )}
                </span>
                {isSelected && <Check className="w-3.5 h-3.5 shrink-0 text-emerald-400" />}
              </button>
            );
          })
        )}
      </div>

      <div className="px-2.5 py-1 border-t border-slate-800/80 bg-slate-950/50 flex items-center justify-between text-[10px] text-slate-500">
        <span>↑↓ 选择 · Enter 确认 · Esc 关闭</span>
        <span>
          已选 {selectedFiles.length}/{MAX_CONTEXT_FILES_PER_MSG}
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Drag & Drop Overlay
// ---------------------------------------------------------------------------

export function DragDropOverlay({ visible }: { visible: boolean }) {
  if (!visible) return null;
  return (
    <div className="pointer-events-none absolute inset-2 z-40 rounded-2xl border-2 border-dashed border-sky-400/80 bg-slate-950/85 backdrop-blur-sm flex flex-col items-center justify-center gap-2 text-center px-4">
      <div className="h-11 w-11 rounded-2xl bg-sky-500/20 border border-sky-400/40 flex items-center justify-center text-sky-300">
        <Upload className="w-5 h-5" />
      </div>
      <div className="text-sm font-medium text-sky-100">松开鼠标即可上传附件</div>
      <div className="text-[11px] text-slate-400 max-w-xs">
        支持图片、PDF、代码、文档、音视频与压缩包（自动挂载至当前消息）
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Image Lightbox Modal
// ---------------------------------------------------------------------------

export function ImageLightboxModal({
  image,
  onClose,
}: {
  image: { src: string; name: string } | null;
  onClose: () => void;
}) {
  useEffect(() => {
    if (!image) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [image, onClose]);

  if (!image) return null;
  const downloadHref = image.src.startsWith("/api/chat/attachments/")
    ? `${image.src}?download=1`
    : image.src;

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-950/90 backdrop-blur-sm flex flex-col items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="max-w-[92vw] max-h-[88vh] flex flex-col items-center gap-3"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="w-full flex items-center justify-between gap-3 text-xs text-slate-200">
          <span className="truncate font-medium max-w-[65vw]">{image.name}</span>
          <div className="flex items-center gap-2 shrink-0">
            <a
              href={downloadHref}
              download={image.name}
              className="h-7 px-2.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-200 inline-flex items-center gap-1"
            >
              <Download className="w-3.5 h-3.5" />
              下载原图
            </a>
            <button
              type="button"
              onClick={onClose}
              className="h-7 w-7 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-200 inline-flex items-center justify-center cursor-pointer"
              aria-label="关闭大图预览"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
        <img
          src={image.src}
          alt={image.name}
          className="max-w-[90vw] max-h-[78vh] rounded-xl border border-slate-800 shadow-2xl object-contain bg-slate-950"
        />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Message Bubble Attachments & Workspace Context Renderer
// ---------------------------------------------------------------------------

export function MessageAttachmentsDisplay({
  attachments,
  contextFiles,
  onPreviewImage,
}: {
  attachments?: ChatAttachmentItem[];
  contextFiles?: string[];
  onPreviewImage: (src: string, name: string) => void;
}) {
  const atts = attachments || [];
  const ctxs = contextFiles || [];
  if (atts.length === 0 && ctxs.length === 0) return null;

  const images = atts.filter((a) => a.kind === "image" && a.preview_url);
  const nonImages = atts.filter((a) => !(a.kind === "image" && a.preview_url));

  return (
    <div className="mb-2 space-y-1.5">
      {images.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {images.map((img) => (
            <button
              key={img.id}
              type="button"
              onClick={() => onPreviewImage(img.preview_url, img.name)}
              title={`${img.name}${img.size_label ? ` (${img.size_label})` : ""}`}
              className="group relative rounded-xl overflow-hidden border border-slate-700/80 bg-slate-950/80 cursor-pointer max-w-[160px] sm:max-w-[200px]"
            >
              <img
                src={img.preview_url}
                alt={img.name}
                loading="lazy"
                className="h-24 sm:h-28 w-auto max-w-full object-cover block"
              />
              <span className="absolute inset-x-0 bottom-0 px-1.5 py-0.5 bg-slate-950/75 text-[10px] text-slate-200 truncate text-left">
                {img.name}
              </span>
            </button>
          ))}
        </div>
      )}

      {(nonImages.length > 0 || ctxs.length > 0) && (
        <div className="flex flex-wrap gap-1.5">
          {nonImages.map((att) => {
            const style = kindChipStyle(att.kind);
            const Icon = style.Icon;
            const sizeTxt = att.size_label || formatBytesCompact(att.size);
            const href = att.preview_url ? `${att.preview_url}?download=1` : undefined;
            return (
              <a
                key={att.id}
                href={href}
                download={att.name}
                className={`inline-flex items-center gap-1.5 max-w-[220px] rounded-lg border px-2 py-1 text-[11px] transition-opacity hover:opacity-90 ${style.border} ${style.bg} ${style.text}`}
              >
                <Icon className="w-3.5 h-3.5 shrink-0" />
                <span className="truncate font-medium">{att.name}</span>
                {sizeTxt && <span className="text-[10px] opacity-75 font-mono shrink-0">{sizeTxt}</span>}
              </a>
            );
          })}

          {ctxs.map((rel) => (
            <span
              key={rel}
              title={`引用工作区文件: @${rel}`}
              className="inline-flex items-center gap-1 max-w-[230px] rounded-lg border border-cyan-500/35 bg-cyan-500/12 px-2 py-1 text-[11px] font-mono text-cyan-200"
            >
              <AtSign className="w-3 h-3 shrink-0 text-cyan-400" />
              <span className="truncate">{rel}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

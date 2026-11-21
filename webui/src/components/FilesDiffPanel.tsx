import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  FileCode,
  FileText,
  Folder,
  FolderOpen,
  GitCompare,
  Loader2,
  Lock,
  Quote,
  RefreshCw,
  RotateCcw,
  RotateCw,
  X,
} from "lucide-react";
import {
  StudioApiError,
  applyUndoCheckpoint,
  fetchFileContent,
  fetchFileDiff,
  fetchFileTree,
  fetchProjects,
  fetchUndoCheckpoints,
  redoUndoCheckpoint,
} from "../api";
import type {
  FileContentResponse,
  FileDiffResponse,
  FileTreeNode,
  StudioSession,
  UndoCheckpointItem,
  UndoCheckpointsResponse,
  WorkspaceProjectItem,
} from "../types";
import { SafeMarkdown } from "./SafeMarkdown";

export interface FilesDiffPanelProps {
  session: StudioSession;
  selectedProject?: string;
  selectedBot?: string;
  activeCid?: string | null;
  onProjectChange?: (projectId: string) => void;
  onQuoteToChat?: (snippet: string) => void;
  onClose?: () => void;
  onSessionRevoked?: (reason: string) => void;
}

type PanelTab = "files" | "diff" | "undo";

function formatFileSize(bytes: number | null): string {
  if (bytes == null || bytes < 0) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTs(ts: number): string {
  if (!ts) return "—";
  try {
    return new Date(ts * 1000).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return String(ts);
  }
}

function mergeDirChildren(
  nodes: FileTreeNode[],
  targetPath: string,
  children: FileTreeNode[],
): FileTreeNode[] {
  return nodes.map((n) => {
    if (n.type === "dir" && n.path === targetPath) {
      return { ...n, children, has_children: children.length > 0 };
    }
    if (n.children && n.children.length > 0) {
      return { ...n, children: mergeDirChildren(n.children, targetPath, children) };
    }
    return n;
  });
}

export function FilesDiffPanel({
  session,
  selectedProject,
  selectedBot,
  activeCid,
  onProjectChange,
  onQuoteToChat,
  onClose,
  onSessionRevoked,
}: FilesDiffPanelProps) {
  const isReadonly = session.role !== "admin";

  const [tab, setTab] = useState<PanelTab>("files");
  const [projects, setProjects] = useState<WorkspaceProjectItem[]>([]);
  const [projectId, setProjectId] = useState<string>(selectedProject || "");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [noticeMsg, setNoticeMsg] = useState<string | null>(null);

  // Files tab state
  const [treeEntries, setTreeEntries] = useState<FileTreeNode[]>([]);
  const [treeTruncated, setTreeTruncated] = useState(false);
  const [treeLoading, setTreeLoading] = useState(false);
  const [expandedDirs, setExpandedDirs] = useState<Record<string, boolean>>({});
  const [loadingDirs, setLoadingDirs] = useState<Record<string, boolean>>({});
  const [selectedFilePath, setSelectedFilePath] = useState<string>("");
  const [fileContent, setFileContent] = useState<FileContentResponse | null>(null);
  const [fileLoading, setFileLoading] = useState(false);
  const [renderMarkdown, setRenderMarkdown] = useState(false);
  const [selStart, setSelStart] = useState<number | null>(null);
  const [selEnd, setSelEnd] = useState<number | null>(null);

  // Diff tab state
  const [diffScope, setDiffScope] = useState<"all" | "staged" | "unstaged">("all");
  const [diffPathFilter, setDiffPathFilter] = useState<string>("");
  const [diffData, setDiffData] = useState<FileDiffResponse | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);

  // Undo/Redo tab state
  const [undoData, setUndoData] = useState<UndoCheckpointsResponse | null>(null);
  const [undoLoading, setUndoLoading] = useState(false);
  const [undoBusyId, setUndoBusyId] = useState<string | null>(null);
  const [conflictPrompt, setConflictPrompt] = useState<{
    action: "undo" | "redo";
    item: UndoCheckpointItem;
    conflicts: string[];
    message: string;
  } | null>(null);

  const mountedRef = useRef(true);
  const projectIdRef = useRef<string>(projectId);
  projectIdRef.current = projectId;
  const treeSeqRef = useRef(0);
  const dirSeqRef = useRef(0);
  const dirReqByPathRef = useRef<Record<string, number>>({});
  const fileSeqRef = useRef(0);
  const diffSeqRef = useRef(0);
  const undoSeqRef = useRef(0);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const handleAuthErr = useCallback(
    (err: unknown) => {
      if (err instanceof StudioApiError && (err.status === 401 || err.status === 403)) {
        if (err.source === "studio_auth" && onSessionRevoked) {
          onSessionRevoked(err.message || "会话已失效，请重新登录");
          return true;
        }
      }
      return false;
    },
    [onSessionRevoked],
  );

  // Sync external selectedProject prop when provided
  useEffect(() => {
    if (selectedProject && selectedProject !== projectId) {
      setProjectId(selectedProject);
    }
  }, [selectedProject, projectId]);

  // Load allowed projects
  useEffect(() => {
    let cancelled = false;
    void fetchProjects()
      .then((res) => {
        if (cancelled) return;
        const list = res.projects || [];
        setProjects(list);
        setProjectId((cur) => {
          if (cur && list.some((p) => p.id === cur)) return cur;
          return list[0]?.id || "";
        });
      })
      .catch((err) => {
        if (!cancelled && !handleAuthErr(err)) {
          setErrorMsg(err instanceof Error ? err.message : "加载项目列表失败");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [handleAuthErr]);

  const loadTree = useCallback(async () => {
    const reqSeq = ++treeSeqRef.current;
    const reqProj = projectId;
    dirReqByPathRef.current = {};
    if (!reqProj) {
      setTreeEntries([]);
      setTreeTruncated(false);
      setTreeLoading(false);
      return;
    }
    setTreeLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetchFileTree({ project_id: reqProj, depth: 2 });
      if (
        !mountedRef.current ||
        treeSeqRef.current !== reqSeq ||
        projectIdRef.current !== reqProj
      ) {
        return;
      }
      setTreeEntries(res.entries || []);
      setTreeTruncated(Boolean(res.truncated));
    } catch (err) {
      if (
        !mountedRef.current ||
        treeSeqRef.current !== reqSeq ||
        projectIdRef.current !== reqProj
      ) {
        return;
      }
      if (!handleAuthErr(err)) {
        setErrorMsg(err instanceof Error ? err.message : "加载目录树失败");
      }
    } finally {
      if (
        mountedRef.current &&
        treeSeqRef.current === reqSeq &&
        projectIdRef.current === reqProj
      ) {
        setTreeLoading(false);
      }
    }
  }, [projectId, handleAuthErr]);

  const loadDiff = useCallback(async () => {
    const reqSeq = ++diffSeqRef.current;
    const reqProj = projectId;
    if (!reqProj) {
      setDiffData(null);
      setDiffLoading(false);
      return;
    }
    setDiffLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetchFileDiff({
        project_id: reqProj,
        scope: diffScope,
        path: diffPathFilter || undefined,
      });
      if (
        !mountedRef.current ||
        diffSeqRef.current !== reqSeq ||
        projectIdRef.current !== reqProj
      ) {
        return;
      }
      setDiffData(res);
    } catch (err) {
      if (
        !mountedRef.current ||
        diffSeqRef.current !== reqSeq ||
        projectIdRef.current !== reqProj
      ) {
        return;
      }
      if (!handleAuthErr(err)) {
        setErrorMsg(err instanceof Error ? err.message : "加载 Git Diff 失败");
      }
    } finally {
      if (
        mountedRef.current &&
        diffSeqRef.current === reqSeq &&
        projectIdRef.current === reqProj
      ) {
        setDiffLoading(false);
      }
    }
  }, [projectId, diffScope, diffPathFilter, handleAuthErr]);

  const loadUndo = useCallback(async () => {
    const reqSeq = ++undoSeqRef.current;
    const reqProj = projectId;
    if (isReadonly) {
      setUndoData(null);
      setUndoLoading(false);
      return;
    }
    setUndoLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetchUndoCheckpoints({
        bot: selectedBot || undefined,
        cid: activeCid || undefined,
        project_id: reqProj || undefined,
      });
      if (
        !mountedRef.current ||
        undoSeqRef.current !== reqSeq ||
        projectIdRef.current !== reqProj
      ) {
        return;
      }
      setUndoData(res);
    } catch (err) {
      if (
        !mountedRef.current ||
        undoSeqRef.current !== reqSeq ||
        projectIdRef.current !== reqProj
      ) {
        return;
      }
      if (!handleAuthErr(err)) {
        setErrorMsg(err instanceof Error ? err.message : "加载撤销检查点失败");
      }
    } finally {
      if (
        mountedRef.current &&
        undoSeqRef.current === reqSeq &&
        projectIdRef.current === reqProj
      ) {
        setUndoLoading(false);
      }
    }
  }, [isReadonly, selectedBot, activeCid, projectId, handleAuthErr]);

  // Reset file preview and invalidate in-flight requests when project changes
  useEffect(() => {
    projectIdRef.current = projectId;
    treeSeqRef.current += 1;
    dirSeqRef.current += 1;
    dirReqByPathRef.current = {};
    fileSeqRef.current += 1;
    diffSeqRef.current += 1;
    undoSeqRef.current += 1;
    setSelectedFilePath("");
    setFileContent(null);
    setFileLoading(false);
    setSelStart(null);
    setSelEnd(null);
    setExpandedDirs({});
    setLoadingDirs({});
    setDiffPathFilter("");
    setDiffData(null);
    setDiffLoading(false);
    setTreeLoading(false);
    setConflictPrompt(null);
  }, [projectId]);

  useEffect(() => {
    if (tab === "files") {
      void loadTree();
    } else if (tab === "diff") {
      void loadDiff();
    } else if (tab === "undo") {
      void loadUndo();
    }
  }, [tab, loadTree, loadDiff, loadUndo]);

  const handleToggleDir = async (node: FileTreeNode) => {
    const nextOpen = !expandedDirs[node.path];
    setExpandedDirs((prev) => ({ ...prev, [node.path]: nextOpen }));
    const reqProj = projectId;
    if (nextOpen && !node.children && reqProj) {
      const reqSeq = ++dirSeqRef.current;
      const reqTreeSeq = treeSeqRef.current;
      dirReqByPathRef.current[node.path] = reqSeq;
      setLoadingDirs((prev) => ({ ...prev, [node.path]: true }));
      try {
        const res = await fetchFileTree({
          project_id: reqProj,
          dir: node.path,
          depth: 2,
        });
        if (
          !mountedRef.current ||
          projectIdRef.current !== reqProj ||
          treeSeqRef.current !== reqTreeSeq ||
          dirReqByPathRef.current[node.path] !== reqSeq
        ) {
          return;
        }
        setTreeEntries((prev) => mergeDirChildren(prev, node.path, res.entries || []));
      } catch (err) {
        if (
          !mountedRef.current ||
          projectIdRef.current !== reqProj ||
          treeSeqRef.current !== reqTreeSeq ||
          dirReqByPathRef.current[node.path] !== reqSeq
        ) {
          return;
        }
        if (!handleAuthErr(err)) {
          setErrorMsg(err instanceof Error ? err.message : "展开子目录失败");
        }
      } finally {
        if (
          mountedRef.current &&
          projectIdRef.current === reqProj &&
          dirReqByPathRef.current[node.path] === reqSeq
        ) {
          setLoadingDirs((prev) => ({ ...prev, [node.path]: false }));
        }
      }
    }
  };

  const handleOpenFile = async (relPath: string) => {
    const reqProj = projectId;
    if (!reqProj) return;
    const reqSeq = ++fileSeqRef.current;
    setSelectedFilePath(relPath);
    setSelStart(null);
    setSelEnd(null);
    setRenderMarkdown(false);
    setFileLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetchFileContent(reqProj, relPath);
      if (
        !mountedRef.current ||
        fileSeqRef.current !== reqSeq ||
        projectIdRef.current !== reqProj
      ) {
        return;
      }
      setFileContent(res);
    } catch (err) {
      if (
        !mountedRef.current ||
        fileSeqRef.current !== reqSeq ||
        projectIdRef.current !== reqProj
      ) {
        return;
      }
      if (!handleAuthErr(err)) {
        setErrorMsg(err instanceof Error ? err.message : "读取文件失败");
      }
    } finally {
      if (
        mountedRef.current &&
        fileSeqRef.current === reqSeq &&
        projectIdRef.current === reqProj
      ) {
        setFileLoading(false);
      }
    }
  };

  const fileLines = useMemo(() => {
    if (!fileContent || fileContent.is_binary || !fileContent.content) return [];
    return fileContent.content.split("\n");
  }, [fileContent]);

  const handleLineClick = (lineNo: number, shiftKey: boolean) => {
    if (selStart === null) {
      setSelStart(lineNo);
      setSelEnd(lineNo);
      return;
    }
    if (shiftKey || selEnd === selStart) {
      setSelEnd(lineNo);
    } else {
      setSelStart(lineNo);
      setSelEnd(lineNo);
    }
  };

  const normalizedRange = useMemo(() => {
    if (selStart === null) return null;
    const e = selEnd ?? selStart;
    return selStart <= e ? { start: selStart, end: e } : { start: e, end: selStart };
  }, [selStart, selEnd]);

  const handleQuoteSelection = () => {
    if (!onQuoteToChat || !fileContent || fileContent.is_binary) return;
    const range = normalizedRange;
    const startIdx = range ? Math.max(1, range.start) : 1;
    const endIdx = range ? Math.min(fileLines.length, range.end) : Math.min(fileLines.length, 40);
    const slice = fileLines.slice(startIdx - 1, endIdx).join("\n");
    const lang = fileContent.language && fileContent.language !== "text" ? fileContent.language : "";
    const snippet = `引用 \`${fileContent.path}:L${startIdx}-L${endIdx}\`：\n\`\`\`${lang}\n${slice}\n\`\`\``;
    onQuoteToChat(snippet);
    setNoticeMsg(`已引用 ${fileContent.path}:L${startIdx}-L${endIdx} 到对话输入框`);
  };

  const executeUndoAction = async (
    action: "undo" | "redo",
    item: UndoCheckpointItem,
    force = false,
  ) => {
    if (isReadonly) return;
    setUndoBusyId(item.entry_id);
    setErrorMsg(null);
    setNoticeMsg(null);
    setConflictPrompt(null);
    try {
      const reqProj = projectId;
      const payload = {
        entry_id: item.entry_id,
        bot: selectedBot || undoData?.bot || undefined,
        cid: item.cid || activeCid || undefined,
        project_id: item.project_id || reqProj || undefined,
        force,
      };
      const res =
        action === "undo"
          ? await applyUndoCheckpoint(payload)
          : await redoUndoCheckpoint(payload);
      if (!mountedRef.current) return;
      setNoticeMsg(
        `${action === "undo" ? "撤销" : "重做"}成功（涉及 ${res.applied.length} 个文件）`,
      );
      await loadUndo();
      if (mountedRef.current && projectIdRef.current) {
        void loadDiff();
      }
    } catch (err) {
      if (!mountedRef.current) return;
      if (handleAuthErr(err)) return;
      if (
        err instanceof StudioApiError &&
        err.status === 409 &&
        err.code === "conflict" &&
        !force
      ) {
        setConflictPrompt({
          action,
          item,
          conflicts: err.conflicts || [],
          message: err.message,
        });
      } else {
        setErrorMsg(err instanceof Error ? err.message : "撤销/重做操作失败");
      }
    } finally {
      if (mountedRef.current) {
        setUndoBusyId(null);
      }
    }
  };

  const renderTreeNodes = (nodes: FileTreeNode[], depth = 0) =>
    nodes.map((node) => {
      const padLeft = 8 + depth * 12;
      if (node.type === "dir") {
        const isOpen = Boolean(expandedDirs[node.path]);
        const isLoading = Boolean(loadingDirs[node.path]);
        return (
          <div key={node.path}>
            <button
              type="button"
              onClick={() => void handleToggleDir(node)}
              style={{ paddingLeft: `${padLeft}px` }}
              className="w-full flex items-center gap-1.5 py-1 pr-2 text-left text-xs text-slate-300 hover:bg-slate-800/70 rounded cursor-pointer"
            >
              {isLoading ? (
                <Loader2 className="w-3 h-3 animate-spin text-sky-400 shrink-0" />
              ) : isOpen ? (
                <ChevronDown className="w-3 h-3 text-slate-500 shrink-0" />
              ) : (
                <ChevronRight className="w-3 h-3 text-slate-500 shrink-0" />
              )}
              {isOpen ? (
                <FolderOpen className="w-3.5 h-3.5 text-amber-400/90 shrink-0" />
              ) : (
                <Folder className="w-3.5 h-3.5 text-amber-400/80 shrink-0" />
              )}
              <span className="truncate">{node.name}</span>
            </button>
            {isOpen && node.children && node.children.length > 0 && (
              <div>{renderTreeNodes(node.children, depth + 1)}</div>
            )}
          </div>
        );
      }
      const selected = selectedFilePath === node.path;
      return (
        <button
          key={node.path}
          type="button"
          onClick={() => void handleOpenFile(node.path)}
          style={{ paddingLeft: `${padLeft + 14}px` }}
          className={`w-full flex items-center justify-between gap-1.5 py-1 pr-2 text-left text-xs rounded cursor-pointer ${
            selected
              ? "bg-sky-500/20 text-sky-200 border border-sky-500/30"
              : "text-slate-300 hover:bg-slate-800/70"
          }`}
        >
          <span className="inline-flex items-center gap-1.5 min-w-0">
            <FileText className="w-3.5 h-3.5 text-slate-500 shrink-0" />
            <span className="truncate font-mono text-[11px]">{node.name}</span>
          </span>
          <span className="text-[10px] text-slate-500 shrink-0 font-mono">
            {formatFileSize(node.size)}
          </span>
        </button>
      );
    });

  const diffLines = useMemo(() => {
    if (!diffData?.diff) return [];
    return diffData.diff.split("\n");
  }, [diffData]);

  return (
    <div className="flex-1 min-h-0 flex flex-col bg-slate-950 text-slate-100">
      {/* Panel Header */}
      <div className="shrink-0 px-3 py-2 border-b border-slate-800/90 bg-slate-900/80 space-y-2">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 min-w-0">
            <FileCode className="w-4 h-4 text-sky-400 shrink-0" />
            <span className="text-xs font-semibold truncate">工作区文件 & Diff</span>
          </div>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => {
                if (tab === "files") void loadTree();
                else if (tab === "diff") void loadDiff();
                else void loadUndo();
              }}
              title="刷新"
              className="h-6 w-6 rounded border border-slate-800 bg-slate-950 hover:bg-slate-800 inline-flex items-center justify-center text-slate-300 cursor-pointer"
            >
              <RefreshCw
                className={`w-3 h-3 ${treeLoading || diffLoading || undoLoading ? "animate-spin" : ""}`}
              />
            </button>
            {onClose && (
              <button
                type="button"
                onClick={onClose}
                title="关闭面板"
                className="h-6 w-6 rounded border border-slate-800 bg-slate-950 hover:bg-slate-800 inline-flex items-center justify-center text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={projectId}
            onChange={(e) => {
              const next = e.target.value;
              setProjectId(next);
              onProjectChange?.(next);
            }}
            aria-label="工作区项目"
            className="flex-1 h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
          >
            {projects.length === 0 && <option value="">暂无白名单项目</option>}
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name || p.id} {p.is_git ? "(Git)" : ""}
              </option>
            ))}
          </select>

          <div className="inline-flex rounded-md border border-slate-800 bg-slate-950 p-0.5 text-[11px]">
            <button
              type="button"
              onClick={() => setTab("files")}
              className={`px-2 py-0.5 rounded cursor-pointer ${
                tab === "files"
                  ? "bg-sky-600/30 text-sky-200 font-medium"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              文件
            </button>
            <button
              type="button"
              onClick={() => setTab("diff")}
              className={`px-2 py-0.5 rounded cursor-pointer inline-flex items-center gap-1 ${
                tab === "diff"
                  ? "bg-sky-600/30 text-sky-200 font-medium"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <GitCompare className="w-3 h-3" />
              Diff
            </button>
            <button
              type="button"
              onClick={() => setTab("undo")}
              className={`px-2 py-0.5 rounded cursor-pointer inline-flex items-center gap-1 ${
                tab === "undo"
                  ? "bg-sky-600/30 text-sky-200 font-medium"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <RotateCcw className="w-3 h-3" />
              Undo
            </button>
          </div>
        </div>
      </div>

      {/* Banners */}
      {errorMsg && (
        <div className="shrink-0 px-3 py-2 border-b border-rose-500/30 bg-rose-500/10 text-[11px] text-rose-200 flex items-center justify-between gap-2">
          <span className="inline-flex items-center gap-1.5 min-w-0">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">{errorMsg}</span>
          </span>
          <button
            type="button"
            onClick={() => setErrorMsg(null)}
            className="text-rose-300 underline shrink-0 cursor-pointer"
          >
            关闭
          </button>
        </div>
      )}

      {noticeMsg && (
        <div className="shrink-0 px-3 py-1.5 border-b border-emerald-500/30 bg-emerald-500/10 text-[11px] text-emerald-200 flex items-center justify-between gap-2">
          <span className="truncate">{noticeMsg}</span>
          <button
            type="button"
            onClick={() => setNoticeMsg(null)}
            className="text-emerald-300 underline shrink-0 cursor-pointer"
          >
            关闭
          </button>
        </div>
      )}

      {/* TAB 1: Files Tree & Preview */}
      {tab === "files" && (
        <div className="flex-1 min-h-0 flex flex-col">
          <div className="h-44 shrink-0 border-b border-slate-800/80 overflow-y-auto p-1.5">
            {treeLoading && treeEntries.length === 0 ? (
              <div className="py-6 text-center text-xs text-slate-500">加载目录中…</div>
            ) : treeEntries.length === 0 ? (
              <div className="py-6 text-center text-xs text-slate-500">目录为空或无可见文件</div>
            ) : (
              <>
                {renderTreeNodes(treeEntries)}
                {treeTruncated && (
                  <div className="px-2 py-1 text-[10px] text-amber-300">
                    已达 400 项显示上限，请展开子目录浏览
                  </div>
                )}
              </>
            )}
          </div>

          <div className="flex-1 min-h-0 flex flex-col">
            {fileLoading ? (
              <div className="flex-1 flex items-center justify-center text-xs text-slate-400 gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
                读取文件中…
              </div>
            ) : !fileContent ? (
              <div className="flex-1 flex items-center justify-center text-xs text-slate-500 px-4 text-center">
                点击上方文件以只读预览内容（支持点选起止行并引用到对话）
              </div>
            ) : (
              <>
                <div className="shrink-0 px-3 py-1.5 border-b border-slate-800/80 bg-slate-900/60 flex flex-wrap items-center justify-between gap-1.5">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <span className="font-mono text-[11px] text-slate-200 truncate">
                      {fileContent.path}
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">
                      {formatFileSize(fileContent.size)}
                    </span>
                    {fileContent.truncated && (
                      <span className="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 text-[10px]">
                        已截断
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-1.5">
                    {fileContent.language === "markdown" && !fileContent.is_binary && (
                      <button
                        type="button"
                        onClick={() => setRenderMarkdown((v) => !v)}
                        className="px-2 py-0.5 rounded border border-slate-700 bg-slate-900 hover:bg-slate-800 text-[11px] text-slate-300 cursor-pointer"
                      >
                        {renderMarkdown ? "源码视图" : "MD 预览"}
                      </button>
                    )}
                    {onQuoteToChat && !fileContent.is_binary && (
                      <button
                        type="button"
                        onClick={handleQuoteSelection}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-sky-600 hover:bg-sky-500 text-white text-[11px] font-medium cursor-pointer"
                      >
                        <Quote className="w-3 h-3" />
                        {normalizedRange
                          ? `引用 L${normalizedRange.start}-L${normalizedRange.end}`
                          : "引用到对话"}
                      </button>
                    )}
                  </div>
                </div>

                <div className="flex-1 min-h-0 overflow-auto p-2">
                  {fileContent.is_binary ? (
                    <div className="py-10 text-center text-xs text-slate-400">
                      二进制文件（{formatFileSize(fileContent.size)}），已拦截原始字节预览。
                    </div>
                  ) : renderMarkdown && fileContent.language === "markdown" ? (
                    <div className="px-2 py-1">
                      <SafeMarkdown content={fileContent.content} />
                    </div>
                  ) : (
                    <div className="font-mono text-[11px] leading-5">
                      {fileLines.map((ln, idx) => {
                        const lineNo = idx + 1;
                        const inSel =
                          normalizedRange !== null &&
                          lineNo >= normalizedRange.start &&
                          lineNo <= normalizedRange.end;
                        return (
                          <div
                            key={lineNo}
                            onClick={(e) => handleLineClick(lineNo, e.shiftKey)}
                            className={`flex gap-2 px-1 rounded cursor-pointer select-text ${
                              inSel ? "bg-sky-500/20" : "hover:bg-slate-800/50"
                            }`}
                          >
                            <span className="w-8 shrink-0 text-right text-slate-600 select-none">
                              {lineNo}
                            </span>
                            <span className="whitespace-pre text-slate-200">{ln || " "}</span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: Git Diff */}
      {tab === "diff" && (
        <div className="flex-1 min-h-0 flex flex-col">
          <div className="shrink-0 px-3 py-2 border-b border-slate-800/80 flex items-center justify-between gap-2">
            <div className="inline-flex rounded-md border border-slate-800 bg-slate-900 p-0.5 text-[11px]">
              {(["all", "staged", "unstaged"] as const).map((sc) => (
                <button
                  key={sc}
                  type="button"
                  onClick={() => setDiffScope(sc)}
                  className={`px-2 py-0.5 rounded cursor-pointer ${
                    diffScope === sc
                      ? "bg-sky-600/30 text-sky-200 font-medium"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {sc === "all" ? "全部" : sc === "staged" ? "已暂存" : "未暂存"}
                </button>
              ))}
            </div>
            {diffPathFilter && (
              <button
                type="button"
                onClick={() => setDiffPathFilter("")}
                className="text-[11px] text-sky-300 hover:underline cursor-pointer truncate"
              >
                清除筛选: {diffPathFilter}
              </button>
            )}
          </div>

          {diffData && !diffData.is_git ? (
            <div className="flex-1 flex items-center justify-center text-xs text-slate-500">
              当前项目不是 Git 仓库
            </div>
          ) : (
            <div className="flex-1 min-h-0 flex flex-col">
              {diffData && diffData.files.length > 0 && (
                <div className="max-h-28 shrink-0 overflow-y-auto border-b border-slate-800/80 p-1.5 space-y-0.5">
                  {diffData.files.map((f) => (
                    <button
                      key={`${f.status}-${f.path}`}
                      type="button"
                      onClick={() =>
                        setDiffPathFilter((cur) => (cur === f.path ? "" : f.path))
                      }
                      className={`w-full flex items-center justify-between gap-2 px-2 py-1 rounded text-[11px] font-mono cursor-pointer ${
                        diffPathFilter === f.path
                          ? "bg-sky-500/20 text-sky-200"
                          : "text-slate-300 hover:bg-slate-800/60"
                      }`}
                    >
                      <span className="truncate">{f.path}</span>
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-amber-300 text-[10px] shrink-0">
                        {f.status}
                      </span>
                    </button>
                  ))}
                </div>
              )}

              <div className="flex-1 min-h-0 overflow-auto p-2 font-mono text-[11px] leading-5">
                {diffLoading ? (
                  <div className="py-8 text-center text-xs text-slate-400">计算 Diff 中…</div>
                ) : diffLines.length === 0 ? (
                  <div className="py-8 text-center text-xs text-slate-500">工作区干净，无 Diff 变更</div>
                ) : (
                  <>
                    {diffData?.truncated && (
                      <div className="mb-2 px-2 py-1 rounded bg-amber-500/15 text-amber-200 text-[11px]">
                        Diff 内容超过 256 KiB 上限，已安全截断
                      </div>
                    )}
                    {diffLines.map((line, i) => {
                      let cls = "text-slate-300";
                      if (line.startsWith("+") && !line.startsWith("+++")) {
                        cls = "bg-emerald-500/15 text-emerald-300";
                      } else if (line.startsWith("-") && !line.startsWith("---")) {
                        cls = "bg-rose-500/15 text-rose-300";
                      } else if (line.startsWith("@@") || line.startsWith("diff --git")) {
                        cls = "bg-sky-500/10 text-sky-300 font-semibold";
                      }
                      return (
                        <div key={i} className={`whitespace-pre px-1 ${cls}`}>
                          {line || " "}
                        </div>
                      );
                    })}
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: Undo / Redo Checkpoints */}
      {tab === "undo" && (
        <div className="flex-1 min-h-0 overflow-y-auto p-3 space-y-3">
          {isReadonly ? (
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200 flex items-center gap-2">
              <Lock className="w-4 h-4 shrink-0" />
              <span>只读权限（readonly）不可查看或执行工作区 Undo/Redo 回滚。</span>
            </div>
          ) : (
            <>
              {conflictPrompt && (
                <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-3 space-y-2 text-xs">
                  <div className="font-semibold text-amber-200 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    检测到外部改动冲突
                  </div>
                  <p className="text-amber-100/90 text-[11px]">{conflictPrompt.message}</p>
                  {conflictPrompt.conflicts.length > 0 && (
                    <ul className="list-disc pl-4 space-y-0.5 font-mono text-[11px] text-amber-200">
                      {conflictPrompt.conflicts.map((c, idx) => (
                        <li key={idx}>{c}</li>
                      ))}
                    </ul>
                  )}
                  <div className="flex items-center gap-2 pt-1">
                    <button
                      type="button"
                      disabled={undoBusyId !== null}
                      onClick={() =>
                        void executeUndoAction(
                          conflictPrompt.action,
                          conflictPrompt.item,
                          true,
                        )
                      }
                      className="px-2.5 py-1 rounded-md bg-rose-600 hover:bg-rose-500 text-white text-[11px] font-medium cursor-pointer"
                    >
                      确认强制覆盖 (Force)
                    </button>
                    <button
                      type="button"
                      onClick={() => setConflictPrompt(null)}
                      className="px-2.5 py-1 rounded-md border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-300 text-[11px] cursor-pointer"
                    >
                      取消
                    </button>
                  </div>
                </div>
              )}

              {undoData && !undoData.ipc_online && (
                <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-3 text-xs text-slate-400">
                  当前目标 Bot Bridge IPC 离线，暂无可用检查点。
                </div>
              )}

              <div className="space-y-2">
                <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                  可撤销检查点 ({undoData?.undo_stack.length || 0})
                </div>
                {(undoData?.undo_stack || []).length === 0 ? (
                  <div className="text-xs text-slate-500 py-2">暂无可撤销的检查点</div>
                ) : (
                  (undoData?.undo_stack || []).map((item) => (
                    <div
                      key={item.entry_id}
                      className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5 space-y-1.5"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <div className="text-xs text-slate-100 truncate">
                            {item.prompt || item.entry_id}
                          </div>
                          <div className="text-[10px] font-mono text-slate-500">
                            {item.entry_id} · {formatTs(item.ts)} · {item.changes_count} 个文件
                          </div>
                        </div>
                        <button
                          type="button"
                          disabled={!item.is_top || undoBusyId !== null}
                          onClick={() => void executeUndoAction("undo", item, false)}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white text-[11px] shrink-0 cursor-pointer"
                        >
                          <RotateCcw className="w-3 h-3" />
                          {item.is_top ? "撤销" : "非栈顶"}
                        </button>
                      </div>
                      {item.changes.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {item.changes.slice(0, 6).map((ch, idx) => (
                            <span
                              key={idx}
                              className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-300"
                            >
                              {ch.action}: {ch.path}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>

              <div className="space-y-2 pt-2 border-t border-slate-800/80">
                <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                  可重做检查点 ({undoData?.redo_stack.length || 0})
                </div>
                {(undoData?.redo_stack || []).length === 0 ? (
                  <div className="text-xs text-slate-500 py-2">暂无可重做的检查点</div>
                ) : (
                  (undoData?.redo_stack || []).map((item) => (
                    <div
                      key={item.entry_id}
                      className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5 flex items-center justify-between gap-2"
                    >
                      <div className="min-w-0">
                        <div className="text-xs text-slate-200 truncate">
                          {item.prompt || item.entry_id}
                        </div>
                        <div className="text-[10px] font-mono text-slate-500">
                          {item.entry_id} · {item.changes_count} 个文件
                        </div>
                      </div>
                      <button
                        type="button"
                        disabled={!item.is_top || undoBusyId !== null}
                        onClick={() => void executeUndoAction("redo", item, false)}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white text-[11px] shrink-0 cursor-pointer"
                      >
                        <RotateCw className="w-3 h-3" />
                        {item.is_top ? "重做" : "非栈顶"}
                      </button>
                    </div>
                  ))
                )}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

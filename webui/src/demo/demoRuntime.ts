import type { BrowserTabInfo, ChatMessageItem, LiveBrowserState } from "../types";
import { finishDemoTurn, getDemoTurn, patchDemoBrowserStatus } from "./mockEventBus";

type ListenerEntry = (ev: Event) => void;

const APP_ROUTE_PATHS = new Set([
  "/",
  "/workspace",
  "/attention",
  "/files",
  "/overview",
  "/browser",
  "/bots",
  "/models",
  "/openbao",
  "/security-card",
  "/jobs",
  "/schedules",
  "/costs",
  "/rooms",
  "/auth/magic",
]);

function installSubpathHistoryGuard(): void {
  const origReplace = window.history.replaceState.bind(window.history);
  const origPush = window.history.pushState.bind(window.history);

  const rewriteUrl = (url: string | URL | null | undefined): string | null => {
    if (url == null) return null;
    const raw = String(url);
    if (!raw.startsWith("/")) return null;
    const cleanPath = raw.split(/[?#]/, 1)[0];
    if (!APP_ROUTE_PATHS.has(cleanPath)) return null;
    const tab = cleanPath === "/" || cleanPath === "/auth/magic" ? "workspace" : cleanPath.slice(1);
    return `#/${tab}`;
  };

  const applySafeHistory = (
    origFn: (data: unknown, unused: string, url?: string | URL | null) => void,
    data: unknown,
    unused: string,
    url?: string | URL | null,
  ): void => {
    const hashTarget = rewriteUrl(url);
    if (hashTarget !== null) {
      if (window.location.protocol === "file:") {
        try {
          window.location.hash = hashTarget;
        } catch {
          // Ignore restricted file:// hash errors
        }
        return;
      }
      const nextUrl = `${window.location.pathname}${window.location.search}${hashTarget}`;
      try {
        origFn(data, unused, nextUrl);
      } catch {
        try {
          window.location.hash = hashTarget;
        } catch {
          // Ignore fallback errors
        }
      }
      return;
    }
    try {
      origFn(data, unused, url);
    } catch {
      // Never throw SecurityError in file:// or sandboxed frames
    }
  };

  window.history.replaceState = function patchedReplaceState(
    data: unknown,
    unused: string,
    url?: string | URL | null,
  ): void {
    applySafeHistory(origReplace, data, unused, url);
  };

  window.history.pushState = function patchedPushState(
    data: unknown,
    unused: string,
    url?: string | URL | null,
  ): void {
    applySafeHistory(origPush, data, unused, url);
  };
}

// ---------------------------------------------------------------------------
// Global EventSource Interceptor (`/api/chat/stream?...`)
// ---------------------------------------------------------------------------

class DemoEventSource {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSED = 2;

  readonly CONNECTING = 0;
  readonly OPEN = 1;
  readonly CLOSED = 2;

  readyState = 0;
  url: string;
  withCredentials = false;
  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;

  private listeners = new Map<string, Set<ListenerEntry>>();
  private timers: number[] = [];
  private closed = false;

  constructor(url: string | URL) {
    this.url = String(url);
    this.bootstrap();
  }

  addEventListener(type: string, listener: ListenerEntry): void {
    let set = this.listeners.get(type);
    if (!set) {
      set = new Set();
      this.listeners.set(type, set);
    }
    set.add(listener);
  }

  removeEventListener(type: string, listener: ListenerEntry): void {
    this.listeners.get(type)?.delete(listener);
  }

  dispatchEvent(ev: Event): boolean {
    const set = this.listeners.get(ev.type);
    if (set) {
      for (const fn of Array.from(set)) {
        try {
          fn(ev);
        } catch {
          // Ignore listener exceptions
        }
      }
    }
    if (ev.type === "open" && this.onopen) this.onopen(ev);
    if (ev.type === "message" && this.onmessage) this.onmessage(ev as MessageEvent);
    if (ev.type === "error" && this.onerror) this.onerror(ev);
    return true;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.readyState = DemoEventSource.CLOSED;
    for (const id of this.timers) {
      window.clearTimeout(id);
    }
    this.timers = [];
  }

  private emit(type: string, payload: Record<string, unknown>): void {
    if (this.closed) return;
    const ev = new MessageEvent(type, { data: JSON.stringify(payload) });
    this.dispatchEvent(ev);
  }

  private schedule(ms: number, fn: () => void): void {
    const id = window.setTimeout(() => {
      if (!this.closed) fn();
    }, ms);
    this.timers.push(id);
  }

  private bootstrap(): void {
    const isChatStream = this.url.startsWith("/api/chat/stream") || this.url.includes("/api/chat/stream?");
    if (!isChatStream) {
      // Fail-closed: never issue real network SSE requests
      this.schedule(10, () => {
        this.readyState = DemoEventSource.CLOSED;
        this.dispatchEvent(new Event("error"));
      });
      return;
    }

    const qIdx = this.url.indexOf("?");
    const qs = new URLSearchParams(qIdx >= 0 ? this.url.slice(qIdx + 1) : "");
    const turnId = qs.get("turn_id") || "";
    const turn = getDemoTurn(turnId);

    if (!turn) {
      this.schedule(20, () => {
        this.readyState = DemoEventSource.OPEN;
        this.dispatchEvent(new Event("open"));
        this.emit("done", {
          conversation_id: "conv-demo-01",
          status: "DONE",
          response: "演示会话流已完成。",
        });
        this.close();
      });
      return;
    }

    const promptPreview = turn.prompt.trim().slice(0, 80);
    const thinking1 = `解析用户请求「${promptPreview}」，定位项目 ${turn.project} 与目标模型 ${turn.model}。`;
    const thinking2 = "\n在离线演示沙箱中模拟工具读取与命令检查，组织结构化 Markdown 回答。";

    const chunks = [
      `已收到你在 **${turn.project}** 工作台的指令：「${promptPreview}」。\n\n`,
      "### 演示执行摘要\n",
      `- **执行节点**：\`${turn.bot}\`（模型 \`${turn.model}\`）\n`,
      "- **离线安全保证**：本次思考链路、工具调用与文本流式输出均由前端内存事件桩实时驱动，零外网调用。\n",
      "- **下一步建议**：可切换到左侧 **「审批中心」** 签核待办，或打开 **「实时浏览器」** 抽屉体验人工接管与网址跳转。\n",
    ];
    const fullResponse = chunks.join("");
    let streamedText = "";

    const handleAbort = () => {
      if (this.closed) return;
      this.emit("aborted", {
        conversation_id: turn.cid,
        partial_text: streamedText,
      });
      this.close();
    };
    turn.abortListeners.add(handleAbort);

    this.schedule(30, () => {
      this.readyState = DemoEventSource.OPEN;
      this.dispatchEvent(new Event("open"));
      const startPayload: Record<string, unknown> = { turn_id: turn.turnId };
      if (!turn.isNewSession) {
        startPayload.conversation_id = turn.cid;
      }
      this.emit("turn_start", startPayload);
      this.emit("init", turn.isNewSession ? {} : { conversation_id: turn.cid });
      this.emit("status", { message: "正在分析上下文与仓库状态…" });
    });

    this.schedule(110, () => {
      this.emit("thinking", { delta: thinking1 });
    });

    this.schedule(210, () => {
      this.emit("thinking", { delta: thinking2 });
      this.emit("tool_use", { tool_name: "read_file" });
    });

    this.schedule(340, () => {
      this.emit("tool_result", { tool_name: "read_file", duration_seconds: 0.2 });
      this.emit("tool_use", { tool_name: "verify_gate" });
    });

    this.schedule(470, () => {
      this.emit("tool_result", { tool_name: "verify_gate", duration_seconds: 0.3 });
    });

    chunks.forEach((chunk, idx) => {
      this.schedule(560 + idx * 80, () => {
        streamedText += chunk;
        this.emit("text_delta", { delta: chunk });
      });
    });

    this.schedule(560 + chunks.length * 80 + 80, () => {
      const assistantMsg: ChatMessageItem = {
        id: `msg-stream-${Date.now().toString(36)}`,
        role: "assistant",
        thinking: thinking1 + thinking2,
        tool_calls: [
          { name: "read_file", duration_seconds: 0.2, active: false },
          { name: "verify_gate", duration_seconds: 0.3, active: false },
        ],
        content: fullResponse,
        status: "DONE",
        created_at: new Date().toISOString(),
      };
      turn.onComplete(assistantMsg, turn.cid);
      finishDemoTurn(turn.turnId);
      this.emit("done", {
        conversation_id: turn.cid,
        status: "DONE",
        response: fullResponse,
      });
      this.close();
    });
  }
}

// ---------------------------------------------------------------------------
// Global WebSocket Interceptor (`/ws/browser` with live Canvas frame streaming)
// ---------------------------------------------------------------------------

interface DemoBrowserTab extends BrowserTabInfo {
  history: string[];
  historyIdx: number;
}

class DemoWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  readonly CONNECTING = 0;
  readonly OPEN = 1;
  readonly CLOSING = 2;
  readonly CLOSED = 3;

  readyState = 0;
  binaryType: BinaryType = "blob";
  url: string;
  protocol = "";
  extensions = "";
  bufferedAmount = 0;

  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;

  private timers: number[] = [];
  private closed = false;
  private clickRipple: { x: number; y: number; count: number } | null = null;
  private scrollY = 0;
  private typedBuffer = "";
  private renderCount = 0;

  private tabs: DemoBrowserTab[] = [
    {
      index: 0,
      title: "AGY-BOT · 交互演示预览",
      url: "https://aibigbigworld.com/agy-bot/demo/",
      active: true,
      history: ["https://aibigbigworld.com/agy-bot/demo/"],
      historyIdx: 0,
    },
    {
      index: 1,
      title: "AGY-BOT · 开源项目主页",
      url: "https://github.com/gaoshanyuhupo/agy-bot",
      active: false,
      history: ["https://github.com/gaoshanyuhupo/agy-bot"],
      historyIdx: 0,
    },
  ];

  private state: LiveBrowserState = {
    running: true,
    session_restricted: false,
    engine_mode: "camoufox_virtual",
    session_gen: 1,
    takeover_gen: 1,
    profile: "demo-profile",
    pinned: true,
    egress: "direct",
    os: "windows",
    takeover: false,
    takeover_reason: "",
    ai_status: "AI 正在巡检展示页",
    ai_busy: true,
    url: "https://aibigbigworld.com/agy-bot/demo/",
    title: "AGY-BOT · 交互演示预览",
    vw: 1280,
    vh: 800,
    tabs: [],
    cursor: { x: 640, y: 340, actor: "ai", kind: "move" },
    quality_preset: "balanced",
    viewers: 1,
  };

  constructor(url: string | URL) {
    this.url = String(url);
    this.syncTabsToState();
    this.bootstrap();
  }

  private schedule(ms: number, fn: () => void): void {
    const id = window.setTimeout(() => {
      if (!this.closed) fn();
    }, ms);
    this.timers.push(id);
  }

  private activeTab(): DemoBrowserTab {
    return this.tabs.find((t) => t.active) || this.tabs[0];
  }

  private syncTabsToState(): void {
    const cur = this.activeTab();
    this.state.url = cur.url;
    this.state.title = cur.title;
    this.state.tabs = this.tabs.map((t, i) => ({
      index: i,
      title: t.title,
      url: t.url,
      active: t.active,
    }));
    patchDemoBrowserStatus({
      running: this.state.running,
      takeover: this.state.takeover,
      ai_busy: this.state.ai_busy,
      url: this.state.url,
      title: this.state.title,
      quality_preset: this.state.quality_preset,
      tabs_count: this.tabs.length,
    });
  }

  private sendJsonToClient(obj: Record<string, unknown>): void {
    if (this.closed || !this.onmessage) return;
    this.onmessage(new MessageEvent("message", { data: JSON.stringify(obj) }));
  }

  private sendStateToClient(): void {
    this.syncTabsToState();
    this.sendJsonToClient({ type: "state", ...this.state });
  }

  private renderAndPushFrame(): void {
    if (this.closed || !this.state.running) return;
    this.renderCount += 1;
    const canvas = document.createElement("canvas");
    canvas.width = this.state.vw;
    canvas.height = this.state.vh;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const w = canvas.width;
    const h = canvas.height;
    const curUrl = this.state.url || "https://aibigbigworld.com/agy-bot/demo/";

    // Background
    const bgGrad = ctx.createLinearGradient(0, 0, w, h);
    bgGrad.addColorStop(0, "#020617");
    bgGrad.addColorStop(0.55, "#0b1224");
    bgGrad.addColorStop(1, "#0f172a");
    ctx.fillStyle = bgGrad;
    ctx.fillRect(0, 0, w, h);

    // Subtle grid lines
    ctx.strokeStyle = "rgba(56, 189, 248, 0.06)";
    ctx.lineWidth = 1;
    for (let gx = 0; gx < w; gx += 64) {
      ctx.beginPath();
      ctx.moveTo(gx, 0);
      ctx.lineTo(gx, h);
      ctx.stroke();
    }
    for (let gy = 0; gy < h; gy += 64) {
      ctx.beginPath();
      ctx.moveTo(0, gy);
      ctx.lineTo(w, gy);
      ctx.stroke();
    }

    // Simulated web page header bar
    ctx.fillStyle = "#0f172a";
    ctx.fillRect(0, 0, w, 68);
    ctx.strokeStyle = "#1e293b";
    ctx.beginPath();
    ctx.moveTo(0, 68);
    ctx.lineTo(w, 68);
    ctx.stroke();

    // Brand dot & title
    ctx.fillStyle = this.state.takeover ? "#34d399" : "#38bdf8";
    ctx.beginPath();
    ctx.arc(42, 34, 10, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle = "#f8fafc";
    ctx.font = "bold 20px system-ui, -apple-system, sans-serif";
    ctx.fillText("AGY-BOT · Live-Browser 实时镜像画布", 66, 41);

    // Mode pill in top-right of simulated page
    const modeLabel = this.state.takeover ? "HUMAN TAKEOVER ACTIVE" : "AI AUTOMATION MIRROR";
    ctx.fillStyle = this.state.takeover ? "rgba(16,185,129,0.22)" : "rgba(14,165,233,0.22)";
    ctx.fillRect(w - 310, 18, 278, 32);
    ctx.strokeStyle = this.state.takeover ? "#34d399" : "#38bdf8";
    ctx.strokeRect(w - 310, 18, 278, 32);
    ctx.fillStyle = this.state.takeover ? "#6ee7b7" : "#7dd3fc";
    ctx.font = "bold 13px monospace";
    ctx.fillText(modeLabel, w - 292, 39);

    // Content shifted by scrollY
    const oy = Math.max(-180, Math.min(0, -this.scrollY));

    // Hero card
    ctx.fillStyle = "rgba(15, 23, 42, 0.92)";
    ctx.fillRect(48, 104 + oy, w - 96, 178);
    ctx.strokeStyle = "#334155";
    ctx.strokeRect(48, 104 + oy, w - 96, 178);

    ctx.fillStyle = "#38bdf8";
    ctx.font = "bold 14px monospace";
    ctx.fillText(`CURRENT URL · ${curUrl}`, 78, 140 + oy);

    ctx.fillStyle = "#f1f5f9";
    ctx.font = "bold 30px system-ui, -apple-system, sans-serif";
    ctx.fillText(this.state.title || "AGY Studio 实时浏览器", 78, 186 + oy);

    ctx.fillStyle = "#94a3b8";
    ctx.font = "16px system-ui, -apple-system, sans-serif";
    ctx.fillText(
      "点击顶栏「人工接管」后，可直接在画布点击、滚轮滚动、键盘输入或在地址栏输入任意 URL 触发实时重绘。",
      78,
      224 + oy,
    );

    ctx.fillStyle = "#64748b";
    ctx.font = "13px monospace";
    ctx.fillText(
      `Frame #${this.renderCount}  |  Quality: ${this.state.quality_preset.toUpperCase()}  |  Scroll: ${this.scrollY}px  |  Tabs: ${this.tabs.length}`,
      78,
      258 + oy,
    );

    // 3 Metric / interactive cards
    const cards = [
      {
        title: "指纹与隔离",
        val: "Camoufox Virtual",
        desc: "单持久化配置 + 直连出口策略",
        accent: "#38bdf8",
      },
      {
        title: "控制权仲裁",
        val: this.state.takeover ? "人工接管中" : "AI 自动驾驶",
        desc: "一键暂停 AI 并接管鼠标 / 键盘输入",
        accent: this.state.takeover ? "#34d399" : "#818cf8",
      },
      {
        title: "交互输入缓冲",
        val: this.typedBuffer ? this.typedBuffer.slice(-24) : "等待键盘 / 点击输入",
        desc: this.clickRipple
          ? `最近点击 (${this.clickRipple.x}, ${this.clickRipple.y})`
          : "点击画布任意位置触发涟漪反馈",
        accent: "#f59e0b",
      },
    ];

    const cardW = Math.floor((w - 96 - 40) / 3);
    cards.forEach((c, idx) => {
      const cx = 48 + idx * (cardW + 20);
      const cy = 312 + oy;
      ctx.fillStyle = "rgba(15, 23, 42, 0.86)";
      ctx.fillRect(cx, cy, cardW, 182);
      ctx.strokeStyle = c.accent;
      ctx.strokeRect(cx, cy, cardW, 182);

      ctx.fillStyle = c.accent;
      ctx.font = "bold 13px monospace";
      ctx.fillText(c.title, cx + 22, cy + 36);

      ctx.fillStyle = "#f8fafc";
      ctx.font = "bold 22px system-ui, -apple-system, sans-serif";
      ctx.fillText(c.val, cx + 22, cy + 84);

      ctx.fillStyle = "#94a3b8";
      ctx.font = "14px system-ui, -apple-system, sans-serif";
      ctx.fillText(c.desc, cx + 22, cy + 128);
    });

    // Interactive preview log block
    ctx.fillStyle = "rgba(2, 6, 23, 0.9)";
    ctx.fillRect(48, 524 + oy, w - 96, 210);
    ctx.strokeStyle = "#1e293b";
    ctx.strokeRect(48, 524 + oy, w - 96, 210);

    ctx.fillStyle = "#34d399";
    ctx.font = "bold 14px monospace";
    ctx.fillText("$ live-browser stream --engine camoufox --mode demo", 74, 562 + oy);

    ctx.fillStyle = "#cbd5e1";
    ctx.font = "14px monospace";
    ctx.fillText(`[OK] WebSocket connected -> /ws/browser (synthetic offline stream)`, 74, 598 + oy);
    ctx.fillText(`[OK] Active route: ${curUrl}`, 74, 628 + oy);
    ctx.fillText(
      `[OK] Control state: takeover=${String(this.state.takeover)} | quality=${this.state.quality_preset}`,
      74,
      658 + oy,
    );
    ctx.fillText(
      `[OK] Zero outbound network requests · Zero real browser profile access`,
      74,
      688 + oy,
    );

    // Click ripple visual feedback
    if (this.clickRipple) {
      ctx.strokeStyle = "#34d399";
      ctx.lineWidth = 3;
      ctx.beginPath();
      ctx.arc(this.clickRipple.x, this.clickRipple.y, 26, 0, Math.PI * 2);
      ctx.stroke();
      ctx.strokeStyle = "rgba(52, 211, 153, 0.45)";
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(this.clickRipple.x, this.clickRipple.y, 44, 0, Math.PI * 2);
      ctx.stroke();
    }

    canvas.toBlob((blob) => {
      if (blob && !this.closed && this.onmessage) {
        this.onmessage(new MessageEvent("message", { data: blob }));
      }
    }, "image/png");
  }

  private bootstrap(): void {
    const cleanPath = this.url.split(/[?#]/, 1)[0];
    if (!cleanPath.endsWith("/ws/browser")) {
      // Fail-closed for any unexpected WebSocket target
      this.schedule(10, () => {
        this.readyState = DemoWebSocket.CLOSED;
        this.onclose?.(new CloseEvent("close", { code: 1006, reason: "offline demo fail-closed" }));
      });
      return;
    }

    this.schedule(25, () => {
      this.readyState = DemoWebSocket.OPEN;
      this.onopen?.(new Event("open"));
      this.sendJsonToClient({ type: "auth_ok", role: "admin" });
      this.sendStateToClient();
      this.renderAndPushFrame();
      // Push a second frame shortly after mount so ResizeObserver / layout rect is guaranteed ready
      this.schedule(140, () => {
        this.renderAndPushFrame();
      });
    });
  }

  send(rawData: string): void {
    if (this.closed || this.readyState !== DemoWebSocket.OPEN) return;
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(rawData) as Record<string, unknown>;
    } catch {
      return;
    }
    const mtype = String(msg.type || "");
    if (mtype === "set_takeover") {
      const active = Boolean(msg.active);
      this.state.takeover = active;
      this.state.ai_busy = !active;
      this.state.takeover_gen += 1;
      this.state.takeover_reason = typeof msg.reason === "string" ? msg.reason : "";
      this.state.cursor = {
        x: this.state.cursor?.x ?? 640,
        y: this.state.cursor?.y ?? 340,
        actor: active ? "human" : "ai",
        kind: "move",
      };
      this.sendJsonToClient({ type: "takeover_ack", ok: true, active });
      this.sendStateToClient();
      this.sendJsonToClient({
        type: "toast",
        message: active ? "🖐 已切换至人工接管模式，可点击画布或输入网址" : "🤖 已将控制权交还 AI",
      });
      this.renderAndPushFrame();
      return;
    }

    if (mtype === "set_quality") {
      const preset = String(msg.preset || "balanced");
      this.state.quality_preset = preset;
      this.sendStateToClient();
      this.sendJsonToClient({ type: "toast", message: `画质预设已切换为 ${preset.toUpperCase()}` });
      this.renderAndPushFrame();
      return;
    }

    if (mtype === "start_browser") {
      this.state.running = true;
      this.state.takeover = Boolean(msg.takeover);
      this.state.session_gen += 1;
      this.sendStateToClient();
      this.renderAndPushFrame();
      return;
    }

    if (mtype === "dialog_response") {
      this.sendJsonToClient({ type: "dialog_closed", dialog_id: String(msg.dialog_id || "") });
      return;
    }

    if (mtype === "input") {
      const action = String(msg.action || "");
      const tab = this.activeTab();
      if (action === "goto" && typeof msg.url === "string" && msg.url.trim()) {
        const nextUrl = msg.url.trim();
        tab.history = tab.history.slice(0, tab.historyIdx + 1);
        tab.history.push(nextUrl);
        tab.historyIdx = tab.history.length - 1;
        tab.url = nextUrl;
        tab.title = `预览 · ${nextUrl.replace(/^https?:\/\//i, "").slice(0, 36)}`;
        this.scrollY = 0;
        this.sendStateToClient();
        this.sendJsonToClient({ type: "toast", message: `已导航至 ${nextUrl}` });
        this.renderAndPushFrame();
      } else if (action === "back" && tab.historyIdx > 0) {
        tab.historyIdx -= 1;
        tab.url = tab.history[tab.historyIdx];
        tab.title = `预览 · ${tab.url.replace(/^https?:\/\//i, "").slice(0, 36)}`;
        this.sendStateToClient();
        this.renderAndPushFrame();
      } else if (action === "forward" && tab.historyIdx < tab.history.length - 1) {
        tab.historyIdx += 1;
        tab.url = tab.history[tab.historyIdx];
        tab.title = `预览 · ${tab.url.replace(/^https?:\/\//i, "").slice(0, 36)}`;
        this.sendStateToClient();
        this.renderAndPushFrame();
      } else if (action === "reload") {
        this.sendJsonToClient({ type: "toast", message: "已刷新演示页面画布" });
        this.renderAndPushFrame();
      } else if (action === "new_tab") {
        for (const t of this.tabs) t.active = false;
        const newUrl = "https://aibigbigworld.com/agy-bot/";
        this.tabs.push({
          index: this.tabs.length,
          title: `新标签页 ${this.tabs.length + 1}`,
          url: newUrl,
          active: true,
          history: [newUrl],
          historyIdx: 0,
        });
        this.sendStateToClient();
        this.renderAndPushFrame();
      } else if (action === "switch_tab" && typeof msg.index === "number") {
        if (msg.index >= 0 && msg.index < this.tabs.length) {
          this.tabs.forEach((t, i) => {
            t.active = i === msg.index;
          });
          this.sendStateToClient();
          this.renderAndPushFrame();
        }
      } else if (action === "close_tab" && typeof msg.index === "number" && this.tabs.length > 1) {
        if (msg.index >= 0 && msg.index < this.tabs.length) {
          this.tabs.splice(msg.index, 1);
          if (!this.tabs.some((t) => t.active)) {
            this.tabs[0].active = true;
          }
          this.sendStateToClient();
          this.renderAndPushFrame();
        }
      } else if (action === "mousedown" || action === "dblclick" || action === "rightclick") {
        const x = typeof msg.x === "number" ? msg.x : 640;
        const y = typeof msg.y === "number" ? msg.y : 340;
        this.clickRipple = { x, y, count: (this.clickRipple?.count || 0) + 1 };
        this.state.cursor = { x, y, actor: "human", kind: action };
        this.sendStateToClient();
        this.renderAndPushFrame();
      } else if (action === "move") {
        const x = typeof msg.x === "number" ? msg.x : 640;
        const y = typeof msg.y === "number" ? msg.y : 340;
        this.state.cursor = { x, y, actor: "human", kind: "move" };
        this.sendStateToClient();
      } else if (action === "wheel") {
        const dy = typeof msg.dy === "number" ? msg.dy : 0;
        this.scrollY = Math.max(0, Math.min(240, this.scrollY + Math.round(dy * 0.4)));
        this.renderAndPushFrame();
      } else if (action === "type" && typeof msg.text === "string") {
        this.typedBuffer = (this.typedBuffer + msg.text).slice(-40);
        this.renderAndPushFrame();
      } else if (action === "press" && typeof msg.key === "string") {
        if (msg.key === "Backspace") {
          this.typedBuffer = this.typedBuffer.slice(0, -1);
        } else if (msg.key === "Enter") {
          this.typedBuffer = "";
        }
        this.renderAndPushFrame();
      }
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.readyState = DemoWebSocket.CLOSED;
    for (const id of this.timers) {
      window.clearTimeout(id);
    }
    this.timers = [];
  }
}

function installFailClosedFetch(): void {
  window.fetch = async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    return new Response(
      JSON.stringify({
        ok: false,
        error: `离线演示模式已拦截外部请求: ${url}`,
        source: "demo_offline_guard",
      }),
      {
        status: 503,
        headers: { "Content-Type": "application/json" },
      },
    );
  };
}

let installed = false;

export function installDemoRuntime(): void {
  if (installed) return;
  installed = true;

  installSubpathHistoryGuard();
  installFailClosedFetch();

  const g = globalThis as unknown as Record<string, unknown>;
  g.EventSource = DemoEventSource;
  g.WebSocket = DemoWebSocket;
}

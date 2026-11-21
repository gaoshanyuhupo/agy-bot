import type {
  BrowserStatusResponse,
  ChatAttachmentItem,
  ChatMessageItem,
  StudioEventEnvelope,
  StudioEventType,
} from "../types";

type EventListenerFn = (ev: StudioEventEnvelope) => void;

const listeners = new Set<EventListenerFn>();
let eventSeq = 100;

export function subscribeDemoEvents(fn: EventListenerFn): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

export function emitDemoEvent(type: StudioEventType, data: Record<string, unknown>): void {
  eventSeq += 1;
  const envelope: StudioEventEnvelope = {
    type,
    seq: eventSeq,
    data,
  };
  for (const fn of Array.from(listeners)) {
    try {
      fn(envelope);
    } catch {
      // Ignore isolated subscriber exceptions in demo mode
    }
  }
}

export interface DemoTurnRecord {
  turnId: string;
  cid: string;
  isNewSession: boolean;
  bot: string;
  prompt: string;
  project: string;
  model: string;
  attachments: ChatAttachmentItem[];
  contextFiles: string[];
  aborted: boolean;
  onComplete: (assistantMsg: ChatMessageItem, resolvedCid: string) => void;
  abortListeners: Set<() => void>;
}

const activeTurns = new Map<string, DemoTurnRecord>();

export function registerDemoTurn(record: DemoTurnRecord): void {
  activeTurns.set(record.turnId, record);
}

export function getDemoTurn(turnId: string): DemoTurnRecord | undefined {
  return activeTurns.get(turnId);
}

export function finishDemoTurn(turnId: string): void {
  activeTurns.delete(turnId);
}

export function abortDemoTurn(turnId: string): boolean {
  const rec = activeTurns.get(turnId);
  if (!rec) return false;
  rec.aborted = true;
  for (const fn of Array.from(rec.abortListeners)) {
    try {
      fn();
    } catch {
      // Ignore listener failure
    }
  }
  rec.abortListeners.clear();
  activeTurns.delete(turnId);
  return true;
}

let sharedBrowserStatus: BrowserStatusResponse = {
  ok: true,
  readonly: false,
  reachable: true,
  running: true,
  session_restricted: false,
  engine_mode: "camoufox_virtual",
  profile: "demo-profile",
  pinned: true,
  egress: "direct",
  os: "windows",
  takeover: false,
  ai_busy: true,
  url: "https://aibigbigworld.com/agy-bot/demo/",
  title: "AGY-BOT · 交互演示预览",
  vw: 1280,
  vh: 800,
  quality_preset: "balanced",
  viewers: 1,
  tabs_count: 2,
};

export function getDemoBrowserStatus(): BrowserStatusResponse {
  return { ...sharedBrowserStatus };
}

export function patchDemoBrowserStatus(patch: Partial<BrowserStatusResponse>): void {
  sharedBrowserStatus = { ...sharedBrowserStatus, ...patch };
}

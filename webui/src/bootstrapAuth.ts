/**
 * First-party magic-link `#t=` fragment capture & deferred Telegram WebApp SDK loader.
 *
 * Security invariants (P0-1):
 * - Runs synchronously at module entry BEFORE React renders or any third-party script loads.
 * - Accepts ONLY `#t=` URL fragment on `/auth/magic` (never `?t=` query strings).
 * - Immediately scrubs `#t=` from `window.location` via `history.replaceState(null, "", "/auth/magic")`.
 * - Dynamically loads `https://telegram.org/js/telegram-web-app.js` ONLY for non-magic flows
 *   (and strictly after verifying no `#t=` fragment remains), using DOM `<script>` creation
 *   without requiring `'unsafe-inline'` in CSP.
 */

const TG_SDK_URL = "https://telegram.org/js/telegram-web-app.js";

let capturedMagicToken: string | null | undefined = undefined;
let telegramSdkPromise: Promise<boolean> | null = null;

/**
 * Synchronously capture `#t=` from `/auth/magic#t=<token>` and immediately clear the URL fragment.
 * Query parameter `?t=` is intentionally NOT accepted or redeemed.
 */
export function captureAndScrubMagicFragment(): string | null {
  if (capturedMagicToken !== undefined) {
    return capturedMagicToken;
  }
  if (window.location.pathname !== "/auth/magic") {
    capturedMagicToken = null;
    return null;
  }
  const hashStr = window.location.hash.replace(/^#/, "");
  const hashParams = new URLSearchParams(hashStr);
  const hashToken = (hashParams.get("t") || "").trim();
  const tok = hashToken || null;
  if (window.location.hash || window.location.search) {
    // Immediately scrub fragment (and any unexpected query) from URL bar / history before any network or script load
    window.history.replaceState(null, "", "/auth/magic");
  }
  capturedMagicToken = tok;
  return tok;
}

export function hasTelegramWebViewHint(): boolean {
  if (window.Telegram?.WebApp?.initData) return true;
  if (window.location.hash.includes("tgWebAppData")) return true;
  if (window.location.search.includes("tgWebApp")) return true;
  const w = window as unknown as Record<string, unknown>;
  if ("TelegramWebviewProxy" in w || "TelegramWebview" in w) return true;
  return false;
}

/**
 * Lazily load the official Telegram WebApp SDK strictly after `#t=` has been scrubbed
 * (and never during magic-link token redemption).
 */
export function loadTelegramSdkOnce(timeoutMs = 2500): Promise<boolean> {
  if (window.Telegram?.WebApp) {
    return Promise.resolve(true);
  }
  // Defense-in-depth: never load third-party SDK while a magic fragment is present
  if (window.location.pathname === "/auth/magic" && window.location.hash) {
    captureAndScrubMagicFragment();
  }
  if (telegramSdkPromise) {
    return telegramSdkPromise;
  }
  telegramSdkPromise = new Promise<boolean>((resolve) => {
    const existing = document.querySelector<HTMLScriptElement>(
      `script[src="${TG_SDK_URL}"]`,
    );
    if (existing) {
      resolve(Boolean(window.Telegram?.WebApp));
      return;
    }
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timer);
      resolve(ok);
    };
    const timer = window.setTimeout(
      () => finish(Boolean(window.Telegram?.WebApp)),
      timeoutMs,
    );
    const script = document.createElement("script");
    script.src = TG_SDK_URL;
    script.async = true;
    script.onload = () => finish(Boolean(window.Telegram?.WebApp));
    script.onerror = () => finish(false);
    document.head.appendChild(script);
  });
  return telegramSdkPromise;
}

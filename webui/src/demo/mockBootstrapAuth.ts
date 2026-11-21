/**
 * Offline demo stub for `bootstrapAuth.ts`.
 * Never reads `/auth/magic` fragments and never injects external Telegram WebApp SDK scripts.
 */

export function captureAndScrubMagicFragment(): string | null {
  return null;
}

export function hasTelegramWebViewHint(): boolean {
  return false;
}

export function loadTelegramSdkOnce(_timeoutMs = 2500): Promise<boolean> {
  return Promise.resolve(false);
}

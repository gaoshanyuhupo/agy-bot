import { useCallback, useEffect, useMemo, useState } from "react";

export const MAX_CLIENT_CHAT_STREAMS = 3;

const activeStreamHolders = new Set<string>();
const listeners = new Set<() => void>();

function notifyListeners(): void {
  for (const fn of listeners) {
    try {
      fn();
    } catch {
      // Ignore subscriber errors
    }
  }
}

export function tryAcquireStreamSlot(holderId: string): boolean {
  if (!holderId) return false;
  if (activeStreamHolders.has(holderId)) {
    return true;
  }
  if (activeStreamHolders.size >= MAX_CLIENT_CHAT_STREAMS) {
    return false;
  }
  activeStreamHolders.add(holderId);
  notifyListeners();
  return true;
}

export function releaseStreamSlot(holderId: string): void {
  if (!holderId) return;
  if (activeStreamHolders.delete(holderId)) {
    notifyListeners();
  }
}

export function getActiveStreamCount(): number {
  return activeStreamHolders.size;
}

export function useStreamBudget(holderId?: string) {
  const [activeCount, setActiveCount] = useState<number>(() => activeStreamHolders.size);
  const [holdsSlot, setHoldsSlot] = useState<boolean>(() =>
    Boolean(holderId && activeStreamHolders.has(holderId)),
  );

  useEffect(() => {
    const onChange = () => {
      setActiveCount(activeStreamHolders.size);
      setHoldsSlot(Boolean(holderId && activeStreamHolders.has(holderId)));
    };
    listeners.add(onChange);
    onChange();
    return () => {
      listeners.delete(onChange);
    };
  }, [holderId]);

  const acquire = useCallback((): boolean => {
    if (!holderId) return false;
    return tryAcquireStreamSlot(holderId);
  }, [holderId]);

  const release = useCallback((): void => {
    if (!holderId) return;
    releaseStreamSlot(holderId);
  }, [holderId]);

  return useMemo(
    () => ({
      activeCount,
      maxStreams: MAX_CLIENT_CHAT_STREAMS,
      holdsSlot,
      acquire,
      release,
    }),
    [activeCount, holdsSlot, acquire, release],
  );
}

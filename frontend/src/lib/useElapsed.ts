import { useEffect, useState } from "react";

// "mm:ss" since `active` last became true — the elapsed clock on a blocking
// request. Measured in this browser from the click, because no endpoint
// reports progress; it says how long we have waited, not how far along it is.
export function useElapsed(active: boolean): string {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    if (!active) return;
    setSeconds(0);
    const started = Date.now();
    const timer = window.setInterval(() => setSeconds(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => window.clearInterval(timer);
  }, [active]);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(Math.floor(seconds / 60))}:${pad(seconds % 60)}`;
}

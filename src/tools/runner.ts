import { spawn } from "child_process";
import { accessSync, constants, existsSync } from "fs";
import { join } from "path";

// ---------------------------------------------------------------------------
// Binary resolution — estate-aware.
// PD_TOOLS_DIR defaults to the yote pdtm install; SHUFFLEDNS_BIN to the
// separate yote go/bin path. Per-binary override: PD_<NAME>_BIN
// (e.g. PD_HTTPX_BIN=/custom/path/httpx).
// ---------------------------------------------------------------------------
export const PD_TOOLS_DIR =
  process.env.PD_TOOLS_DIR || "/home/toxic/.pdtm/go/bin";
export const SHUFFLEDNS_BIN =
  process.env.SHUFFLEDNS_BIN || "/home/toxic/go/bin/shuffledns";

const binCache = new Map<string, string>();

export function resolveBinary(name: string): string {
  const cached = binCache.get(name);
  if (cached) return cached;
  const override = process.env[`PD_${name.toUpperCase()}_BIN`];
  const p = override || (name === "shuffledns" ? SHUFFLEDNS_BIN : join(PD_TOOLS_DIR, name));
  if (!existsSync(p)) {
    throw new Error(
      `binary '${name}' not found at ${p} (set PD_${name.toUpperCase()}_BIN to override)`
    );
  }
  try {
    accessSync(p, constants.X_OK);
  } catch {
    throw new Error(`binary '${name}' at ${p} is not executable`);
  }
  binCache.set(name, p);
  return p;
}

// ---------------------------------------------------------------------------
// Input guards. spawn() never uses a shell, so these are defense-in-depth:
// strip control chars / newlines, cap lengths and counts.
// ---------------------------------------------------------------------------
const CONTROL_RE = /[\0\r\n]/;

export function cleanList(items: unknown, maxItems = 1000, maxLen = 253): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  if (!Array.isArray(items)) return out;
  for (const raw of items) {
    const s = String(raw).trim();
    if (!s || s.length > maxLen || CONTROL_RE.test(s)) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
    if (out.length >= maxItems) break;
  }
  return out;
}

export function cleanDomain(d: unknown): string {
  const s = String(d ?? "").trim().toLowerCase();
  if (!s || s.length > 253 || !/^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/.test(s)) {
    throw new Error(`invalid domain: ${String(d)}`);
  }
  return s;
}

export function cleanPortSpec(p: unknown): string | undefined {
  if (p == null || p === "") return undefined;
  const s = String(p).trim();
  if (!/^[0-9,\- ]+$/.test(s) || s.length > 200) {
    throw new Error(`invalid port spec: ${s}`);
  }
  return s;
}

// ---------------------------------------------------------------------------
// Timeout-guarded binary runner. Absolute path, argv array, stdin pipe.
// Never a shell. Kills the child (SIGKILL) on timeout.
// ---------------------------------------------------------------------------
export interface RunResult {
  lines: string[];
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
}

export function runBinary(
  binary: string,
  args: string[],
  opts: { timeoutMs?: number; stdin?: string } = {}
): Promise<RunResult> {
  const timeoutMs = opts.timeoutMs ?? 300_000;
  return new Promise((resolve) => {
    let bin: string;
    try {
      bin = resolveBinary(binary);
    } catch (err) {
      resolve({
        lines: [],
        stderr: err instanceof Error ? err.message : String(err),
        exitCode: null,
        timedOut: false,
      });
      return;
    }

    const child = spawn(bin, args, { stdio: ["pipe", "pipe", "pipe"] });
    const lines: string[] = [];
    let stderr = "";
    let remainder = "";
    let settled = false;
    let timedOut = false;

    const done = (exitCode: number | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (remainder.trim()) lines.push(remainder);
      resolve({ lines, stderr, exitCode, timedOut });
    };

    const timer = setTimeout(() => {
      timedOut = true;
      stderr += `\n[timeout] killed after ${timeoutMs}ms`;
      child.kill("SIGKILL");
    }, timeoutMs);
    // Don't let the watchdog keep the MCP server alive by itself
    (timer as unknown as { unref?: () => void }).unref?.();

    child.stdout.on("data", (d: Buffer) => {
      remainder += d.toString();
      const parts = remainder.split("\n");
      remainder = parts.pop() ?? "";
      for (const p of parts) if (p.trim()) lines.push(p);
    });
    child.stderr.on("data", (d: Buffer) => {
      stderr += d.toString();
      if (stderr.length > 64_000) stderr = stderr.slice(-64_000);
    });
    child.on("close", (code) => done(code));
    child.on("error", (err) => {
      stderr += `\n[spawn error] ${err.message}`;
      done(null);
    });

    if (opts.stdin != null) {
      child.stdin.write(opts.stdin);
    }
    child.stdin.end();
  });
}

// ---------------------------------------------------------------------------
// JSONL parsing helper: parse each line, keep what pick() accepts.
// ---------------------------------------------------------------------------
export function parseJsonl<T>(lines: string[], pick: (o: any) => T | null): T[] {
  const out: T[] = [];
  const seen = new Set<string>();
  for (const line of lines) {
    let parsed: any;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    const item = pick(parsed);
    if (item == null) continue;
    const key = JSON.stringify(item);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

export function ok<T>(payload: T): { ok: true } & { result: T } {
  return { ok: true, result: payload };
}

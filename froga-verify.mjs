#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// MANTLE standalone verifier. One file, Node built-ins only, and NO
// imports from the MANTLE source tree: canonical JSON, hashing, exact
// decimal arithmetic and the replay compute are all re-implemented here
// so that an independent check is a different implementation, not the
// same code run twice (spec §9).
//
// Usage:
//   node verifier/mantle-verify.mjs <ledger.jsonl> [--pubkey key.pem]
//        [--replay <repo> <data-dir>]
// Exit 0 = valid; 2 = invalid (first failing line index + reason);
// 1 = usage error. Seals are read from seals.jsonl beside the ledger.
import { createHash, verify as cryptoVerify } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

// ---------------- canonical JSON + hashing ----------------
function norm(v, path = "$") {
  if (v === null || typeof v === "string" || typeof v === "boolean") return v;
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new TypeError(`Non-finite number at ${path}`);
    return Object.is(v, -0) ? 0 : v;
  }
  if (Array.isArray(v)) return v.map((x, i) => norm(x, `${path}[${i}]`));
  if (typeof v === "object") {
    const out = {};
    for (const k of Object.keys(v).sort()) {
      if (v[k] === undefined) throw new TypeError(`Undefined value at ${path}.${k}`);
      out[k] = norm(v[k], `${path}.${k}`);
    }
    return out;
  }
  throw new TypeError(`Unsupported canonical value at ${path}: ${typeof v}`);
}
const canon = (v) => JSON.stringify(norm(v));
const sha256hex = (bytes) => createHash("sha256").update(bytes).digest("hex");
const addr = (v) => `sha256:${sha256hex(typeof v === "string" || Buffer.isBuffer(v) ? v : canon(v))}`;

// ---------------- exact decimals (BigInt) ----------------
const DEC_RE = /^-?\d+(\.\d+)?$/;
function parseDec(s) {
  if (typeof s !== "string" || !DEC_RE.test(s)) return null;
  const neg = s.startsWith("-");
  const body = neg ? s.slice(1) : s;
  const dot = body.indexOf(".");
  const whole = dot === -1 ? body : body.slice(0, dot);
  const frac = dot === -1 ? "" : body.slice(dot + 1);
  let int = BigInt(whole + frac);
  if (neg && int !== 0n) int = -int;
  return { int, scale: frac.length };
}
function fmtDec(d) {
  const neg = d.int < 0n;
  let digits = (neg ? -d.int : d.int).toString();
  if (d.scale === 0) return neg ? `-${digits}` : digits;
  digits = digits.padStart(d.scale + 1, "0");
  return `${neg ? "-" : ""}${digits.slice(0, digits.length - d.scale)}.${digits.slice(digits.length - d.scale)}`;
}
function canonDec(d) {
  let { int, scale } = d;
  while (scale > 0 && int % 10n === 0n) { int /= 10n; scale -= 1; }
  return fmtDec({ int, scale });
}
const pow10 = (e) => 10n ** BigInt(e);
function aligned(a, b) {
  const s = Math.max(a.scale, b.scale);
  return [a.int * pow10(s - a.scale), b.int * pow10(s - b.scale), s];
}
const cmpDec = (a, b) => { const [x, y] = aligned(a, b); return x < y ? -1 : x > y ? 1 : 0; };
function sumDec(list) {
  const s = list.reduce((m, d) => Math.max(m, d.scale), 0);
  return { int: list.reduce((acc, d) => acc + d.int * pow10(s - d.scale), 0n), scale: s };
}
function div12(num, den) {
  if (den.int === 0n) throw new Error("DIVIDE_BY_ZERO");
  const exp = den.scale + 12 - num.scale;
  let n = num.int;
  let d = den.int;
  if (exp >= 0) n *= pow10(exp); else d *= pow10(-exp);
  const neg = (n < 0n) !== (d < 0n);
  const an = n < 0n ? -n : n;
  const ad = d < 0n ? -d : d;
  let q = an / ad;
  const r = an % ad;
  if (r * 2n > ad || (r * 2n === ad && q % 2n === 1n)) q += 1n;
  return { int: neg && q !== 0n ? -q : q, scale: 12 };
}

// ---------------- instants (strict ISO-8601, UTC default) ----------------
function parseInstant(value) {
  if (typeof value !== "string") return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?\s*([Zz]|[+-]\d{2}:?\d{2})?)?$/.exec(value.trim());
  if (!m) return null;
  const Y = +m[1], Mo = +m[2], D = +m[3];
  const H = +(m[4] ?? 0), Mi = +(m[5] ?? 0), S = +(m[6] ?? 0);
  const msPart = m[7] ? Number((m[7] + "000").slice(0, 3)) : 0;
  if (Mo < 1 || Mo > 12 || D < 1 || D > 31 || H > 23 || Mi > 59 || S > 60) return null;
  let t = Date.UTC(Y, Mo - 1, D, H, Mi, S, msPart);
  const probe = new Date(t);
  if (probe.getUTCFullYear() !== Y || probe.getUTCMonth() !== Mo - 1 || probe.getUTCDate() !== D) return null;
  const zone = m[8];
  if (zone && zone.toUpperCase() !== "Z") {
    const sign = zone.startsWith("-") ? 1 : -1;
    const digits = zone.replace(":", "").slice(1);
    t += sign * (Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2, 4))) * 60000;
  }
  return t;
}

// Canonical UTC rendering (millisecond precision), as used in receipts.
function formatInstant(ms) {
  return new Date(ms).toISOString();
}

// ---------------- time-intelligence calendar (independent) ----------------
//
// A time-intelligence answer is about a DIFFERENT window than the one
// asked: last March, the year to date, the quarter to date. The
// calendar below is this file's own implementation, not the engine's —
// an independent check is a different implementation, not the same code
// run twice.
//
// Two rules keep it exact:
//
//   1. Everything is integer UTC. A window bound is a month boundary
//      when it is the first instant of a month, and months are counted
//      as integers, so no Date is ever asked to "add a month" and no
//      host timezone can ever touch an answer.
//   2. Only month boundaries ever move. A month-aligned window stays
//      month-aligned when it moves, so there is no month-end clamping
//      to get wrong — not even in a leap year. February 2024 and
//      February 2025 are ordinary months here.
//
// The finest grain is the month. A window that is not month-aligned
// cannot be shifted without a clamping decision that no grain can
// justify, so it is refused rather than rounded.
const TI_GRAIN_MONTHS = Object.freeze({ year: 12, quarter: 3, month: 1 });

// Months per grain: a year is twelve months, a quarter three, a month
// one — so "back one year" and "back twelve months" are the same move,
// which is what lands a March window on March a year earlier.
function tiGrainMonths(grain) {
  const months = TI_GRAIN_MONTHS[grain];
  if (months === undefined) throw new Error(`UNSUPPORTED:GRAIN_${String(grain).toUpperCase()}`);
  return months;
}

// The (year, month) an instant falls in, month 1-based.
function tiMonthKey(ms) {
  const d = new Date(ms);
  return { year: d.getUTCFullYear(), month: d.getUTCMonth() + 1 };
}

// The first instant of a month.
function tiMonthStart(year, month) {
  return Date.UTC(year, month - 1, 1);
}

// Move a month key by a whole number of months. Months are counted as
// a single integer, so December -> January needs no special case.
function tiAddMonths(key, delta) {
  const total = key.year * 12 + (key.month - 1) + delta;
  const year = Math.floor(total / 12);
  return { year, month: total - year * 12 + 1 };
}

// True when an instant is exactly the first instant of a month.
function tiIsMonthStart(ms) {
  const key = tiMonthKey(ms);
  return ms === tiMonthStart(key.year, key.month);
}

// A window is usable for time intelligence only when both bounds are
// month boundaries: one that starts mid-month would need a clamping
// decision no grain can justify.
function tiMonthAligned(window) {
  if (!window || !window.start || !window.end) return false;
  const start = parseInstant(window.start);
  const end = parseInstant(window.end);
  if (start === null || end === null) return false;
  if (start >= end) return false;
  return tiIsMonthStart(start) && tiIsMonthStart(end);
}

// The semantics a window was computed with. A grain shift is MDX member
// semantics, a day offset is dbt's day-level offset, a to-date window
// is a to-date window, and a member navigation is MDX's navigation
// between periods.
function tiSemantics(ti) {
  if (ti && ti.kind === "day_offset") return "dbt_day_offset";
  if (ti && ti.kind === "to_date") return "to_date";
  if (ti && (ti.kind === "member_nav" || ti.kind === "member_set")) return "mdx_member_navigation";
  return "mdx_period_shift";
}

// ---------------------------------------------------------------------------
// Member navigation (independent).
//
// A member navigation reads a base over a period RELATIVE TO THE CURRENT
// MEMBER — the member the question's period declares.
//
// This is this file's own implementation, written differently from the
// engine's on purpose: the engine builds a period from month KEYS and
// moves them, and this one counts months as a single integer index from
// year zero and rebuilds the bounds from that index. The two fail
// differently, which is the point of having two.
// ---------------------------------------------------------------------------

// The month index of an instant: months since year zero, as one integer.
function tiMonthIndex(ms) {
  const key = tiMonthKey(ms);
  return key.year * 12 + (key.month - 1);
}

// The first instant of the month at an index.
function tiMonthStartAt(index) {
  const year = Math.floor(index / 12);
  return tiMonthStart(year, index - year * 12 + 1);
}

// The index of the first month of the grain period that holds a month.
function tiPeriodStartIndex(grain, index) {
  if (grain === "year") return Math.floor(index / 12) * 12;
  if (grain === "quarter") return Math.floor(index / 3) * 3;
  return index;
}

// The current member of a question: the whole period at the question's
// grain that the question's window names.
//
// The window must be EXACTLY one whole period at that grain. A window
// that spans two of them, or half of one, names no member at all.
function tiPeriodContext(askWindow, period) {
  if (!period || !period.grain) return null;
  if (!askWindow || !askWindow.start || !askWindow.end) throw new Error("NEEDS_WINDOW");
  const start = parseInstant(askWindow.start);
  const end = parseInstant(askWindow.end);
  if (start === null || end === null) throw new Error("WINDOW_NOT_ONE_PERIOD");
  if (!tiIsMonthStart(start) || !tiIsMonthStart(end)) throw new Error("WINDOW_NOT_ONE_PERIOD");
  const months = tiGrainMonths(period.grain);
  if (tiMonthIndex(end) - tiMonthIndex(start) !== months) throw new Error("WINDOW_NOT_ONE_PERIOD");
  return { grain: period.grain, index: tiMonthIndex(start) };
}

// The current member at a grain: the question's own current member, or
// the coarser period that holds it. A grain FINER than the question's
// is not determined by the question, so it refuses.
function tiCurrentMember(ctx, grain) {
  const months = tiGrainMonths(grain);
  if (grain === ctx.grain) return { start: ctx.index, end: ctx.index + months };
  if (months > tiGrainMonths(ctx.grain)) {
    const start = tiPeriodStartIndex(grain, ctx.index);
    return { start, end: start + months };
  }
  throw new Error("WINDOW_NOT_ONE_PERIOD");
}

// A period window moved by a whole number of months.
function tiShiftedMember(member, offset) {
  return { start: tiMonthStartAt(member.start + offset), end: tiMonthStartAt(member.end + offset) };
}

// The signed number of months a navigation moves.
function tiNavOffset(nav, grain) {
  const months = tiGrainMonths(grain);
  if (nav.type === "prev") return -months;
  if (nav.type === "next") return months;
  if (nav.type === "lag") return -months * nav.n;
  if (nav.type === "forward") return months * nav.n;
  if (nav.type === "backward") return -months * nav.n;
  throw new Error(`UNSUPPORTED:TI_NAV_${String(nav.type).toUpperCase()}`);
}

// The window a member navigation reads over.
//
// A navigation reads at the question's grain: the current member's
// period, moved. The grain a navigation may carry is the grain of its
// STEP — the level a ParallelPeriod names — not of what it reads.
function tiMemberNavWindow(nav, ctx) {
  const stepGrain = nav.grain ?? ctx.grain;
  const member = tiCurrentMember(ctx, ctx.grain);
  return tiShiftedMember(member, tiNavOffset(nav, stepGrain));
}

// The windows a SET of periods reads over, in order.
function tiMemberSetWindows(set, ctx) {
  const months = tiGrainMonths(ctx.grain);
  const member = tiCurrentMember(ctx, ctx.grain);
  const windows = [];
  if (set.type === "lag_range") {
    for (let k = set.from; k >= set.to; k -= 1) {
      windows.push(tiShiftedMember(member, -months * k));
    }
    return windows;
  }
  if (set.type === "period") {
    // A set of ONE period: the period the navigation names.
    windows.push(tiMemberNavWindow(set.nav, ctx));
    return windows;
  }
  if (set.type === "periods_to_date") {
    // The ANCHOR: a navigation that names the period the to-date runs
    // to. Without one, the current member is the end of the span.
    const anchorOffset = set.anchor
      ? tiNavOffset(set.anchor, set.anchor.grain ?? ctx.grain)
      : 0;
    const anchorIndex = ctx.index + anchorOffset;
    const levelStart = tiPeriodStartIndex(set.grain, anchorIndex);
    const memberStart = tiPeriodStartIndex(ctx.grain, anchorIndex);
    const span = memberStart - levelStart;
    if (span < 0 || span % months !== 0) throw new Error("WINDOW_NOT_ONE_PERIOD");
    const count = span / months + 1;
    const anchorMember = { start: anchorIndex, end: anchorIndex + months };
    for (let k = count - 1; k >= 0; k -= 1) {
      windows.push(tiShiftedMember(anchorMember, -months * k));
    }
    return windows;
  }
  throw new Error(`UNSUPPORTED:TI_SET_${String(set.type).toUpperCase()}`);
}

// A navigation reads at a grain the hierarchy must have a level for.
function tiAssertNavGrain(ti, grain) {
  const grains = ti.grains ?? [];
  if (!grains.includes(grain)) throw new Error("UNSUPPORTED:TIME_LEVEL_UNRESOLVED");
}

// ---------------------------------------------------------------------------
// Day-level offsets (dbt's `offset_window`).
//
// This is this file's own implementation, written differently from the
// engine's on purpose: days are counted as whole days since the epoch
// and rebuilt, and a calendar-year move is done by changing the year on
// a date and then checking that the month and day survived. The engine
// builds a date from components instead, so the two implementations
// fail differently — which is the point of having two.
// ---------------------------------------------------------------------------

const TI_MS_PER_DAY = 86400000;

// True for a Gregorian leap year.
function tiIsLeapYear(year) {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

// The first instant of Feb 29 in a leap year, or null in other years.
function tiFeb29Start(year) {
  if (!tiIsLeapYear(year)) return null;
  return Date.UTC(year, 1, 29);
}

// True when the half-open range [start, end) holds a Feb 29.
function tiContainsFeb29(start, end) {
  if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end) return false;
  const firstYear = new Date(start).getUTCFullYear();
  const lastYear = new Date(end - 1).getUTCFullYear();
  for (let year = firstYear; year <= lastYear; year += 1) {
    const t = tiFeb29Start(year);
    if (t === null) continue;
    if (t >= start && t < end) return true;
  }
  return false;
}

// Move an instant back a whole number of days, keeping the time of day.
function tiMoveDays(ms, days) {
  const dayIndex = Math.floor(ms / TI_MS_PER_DAY);
  const remainder = ms - dayIndex * TI_MS_PER_DAY;
  return (dayIndex + days) * TI_MS_PER_DAY + remainder;
}

// Move an instant back n calendar years, keeping its month and day.
// setUTCFullYear normalizes Feb 29 into March when the target year is
// not a leap year; that normalization IS the ambiguity, so it is
// refused rather than accepted.
function tiMoveYears(ms, n) {
  const d = new Date(ms);
  const moved = new Date(d.getTime());
  moved.setUTCFullYear(d.getUTCFullYear() - n);
  if (moved.getUTCMonth() !== d.getUTCMonth() || moved.getUTCDate() !== d.getUTCDate()) {
    throw new Error("LEAP_DAY_OFFSET_AMBIGUOUS");
  }
  return moved.getTime();
}

// The window a day-level offset reads over.
function tiDayOffsetWindow(start, end, unit, n) {
  if (!Number.isInteger(n) || n < 1) throw new Error("UNSUPPORTED:OFFSET_WINDOW_UNIT");
  if (unit === "day" || unit === "week") {
    const days = unit === "day" ? n : n * 7;
    return { start: tiMoveDays(start, -days), end: tiMoveDays(end, -days) };
  }
  if (unit !== "year") throw new Error("UNSUPPORTED:OFFSET_WINDOW_UNIT");
  // A Feb 29 in the ask window has no counterpart a year back, and a
  // Feb 29 in the shifted window has no counterpart a year forward.
  if (tiContainsFeb29(start, end)) throw new Error("LEAP_DAY_OFFSET_AMBIGUOUS");
  const shiftedStart = tiMoveYears(start, n);
  const shiftedEnd = tiMoveYears(end, n);
  if (tiContainsFeb29(shiftedStart, shiftedEnd)) throw new Error("LEAP_DAY_OFFSET_AMBIGUOUS");
  return { start: shiftedStart, end: shiftedEnd };
}

// The window a time-intelligence node actually computes over, as
// instants. Throws with the engine's refusal code when the question
// cannot be answered by time intelligence at all.
function tiWindowFor(ti, askWindow) {
  if (!askWindow || !askWindow.start || !askWindow.end) throw new Error("NEEDS_WINDOW");
  const start = parseInstant(askWindow.start);
  const end = parseInstant(askWindow.end);
  if (start === null || end === null) throw new Error("WINDOW_NOT_GRAIN_ALIGNED");
  // A day offset is day-level: it does not need a month-aligned window,
  // and it is checked first so a dbt offset is never refused for a
  // reason that belongs to a grain shift.
  if (ti.kind === "day_offset") {
    return tiDayOffsetWindow(start, end, ti.unit, ti.n);
  }
  if (!tiMonthAligned(askWindow)) throw new Error("WINDOW_NOT_GRAIN_ALIGNED");
  if (ti.kind === "shift") {
    // Both bounds move back by n grain units, so the month of the year
    // is preserved: March 2026 at one year is March 2025.
    if (!Number.isInteger(ti.n) || ti.n < 1) throw new Error("WINDOW_NOT_GRAIN_ALIGNED");
    const months = tiGrainMonths(ti.grain) * ti.n;
    const from = tiAddMonths(tiMonthKey(start), -months);
    const to = tiAddMonths(tiMonthKey(end), -months);
    return { start: tiMonthStart(from.year, from.month), end: tiMonthStart(to.year, to.month) };
  }
  if (ti.kind === "to_date") {
    // From the start of the grain period that holds the window's last
    // instant, up to the window's end. A March window at year grain is
    // [2026-01-01, 2026-04-01).
    const key = tiMonthKey(end - 1);
    let period;
    if (ti.grain === "year") period = { year: key.year, month: 1 };
    else if (ti.grain === "quarter") period = { year: key.year, month: Math.floor((key.month - 1) / 3) * 3 + 1 };
    else if (ti.grain === "month") period = { year: key.year, month: key.month };
    else throw new Error(`UNSUPPORTED:GRAIN_${String(ti.grain).toUpperCase()}`);
    return { start: tiMonthStart(period.year, period.month), end };
  }
  throw new Error(`UNSUPPORTED:TI_KIND_${String(ti.kind).toUpperCase()}`);
}

// Every window a time-intelligence node computes over, as instants.
// A shift, a to-date and a day offset have one; a member navigation has
// one; a member set has one per period.
function tiWindowsOf(ti, askWindow, period) {
  if (ti.kind === "member_nav" || ti.kind === "member_set") {
    const ctx = tiPeriodContext(askWindow, period);
    if (!ctx) throw new Error("NEEDS_PERIOD");
    if (ti.kind === "member_set") {
      tiAssertNavGrain(ti, ctx.grain);
      return tiMemberSetWindows(ti.set, ctx);
    }
    const grain = ti.nav?.grain ?? ctx.grain;
    // A navigation reads at the question's grain, so the hierarchy must
    // have a level at it. The grain a navigation may carry is the grain
    // of its STEP, not of what it reads.
    tiAssertNavGrain(ti, ctx.grain);
    return [tiMemberNavWindow(ti.nav, ctx)];
  }
  return [tiWindowFor(ti, askWindow)];
}

// One entry per window a time-intelligence node computed over, in the
// shape the receipt records — so an empty prior year is visible rather
// than hidden. Each entry names the semantics it used.
function tiWindowEntry(ti, baseId, bounds, grain) {
  const entry = {
    kind: ti.kind,
    semantics: tiSemantics(ti),
    base: baseId,
    window: { start: formatInstant(bounds.start), end: formatInstant(bounds.end) }
  };
  if (ti.kind === "day_offset") {
    entry.unit = ti.unit;
    entry.n = ti.n;
    return entry;
  }
  if (ti.kind === "member_nav") {
    entry.grain = ti.nav?.grain ?? grain ?? null;
    entry.nav = { type: ti.nav?.type ?? null, n: ti.nav?.n ?? null };
    return entry;
  }
  if (ti.kind === "member_set") {
    entry.grain = grain ?? null;
    entry.aggregate = ti.aggregate ?? null;
    return entry;
  }
  entry.grain = ti.grain;
  if (ti.kind === "shift") entry.n = ti.n;
  return entry;
}

function tiWindowsFor(def, inputs, askWindow, period, seen = new Set()) {
  const out = [];
  if (!def || typeof def !== "object") return out;
  if (def.operation === "ti") {
    const baseId = def.base?.object_id ?? null;
    for (const bounds of tiWindowsOf(def, askWindow, period)) {
      out.push(tiWindowEntry(def, baseId, bounds, period?.grain ?? null));
    }
    if (baseId && !seen.has(baseId) && inputs) {
      seen.add(baseId);
      const baseIr = inputs[baseId];
      if (baseIr) out.push(...tiWindowsFor(baseIr.definition, inputs, askWindow, period, seen));
    }
    return out;
  }
  if (def.operation === "arith") {
    for (const name of Object.keys(def.operands ?? {}).sort()) {
      const operand = def.operands[name];
      if (operand.ti) {
        for (const bounds of tiWindowsOf(operand.ti, askWindow, period)) {
          out.push(tiWindowEntry(operand.ti, operand.object_id, bounds, period?.grain ?? null));
        }
      }
      const ir = inputs?.[operand.object_id];
      if (!ir || seen.has(operand.object_id)) continue;
      seen.add(operand.object_id);
      out.push(...tiWindowsFor(ir.definition, inputs, askWindow, period, seen));
    }
  }
  return out;
}

// ---------------- data parsing (cells: null|string|bool|{n:raw}) ----------------
function parseCsv(text) {
  const src = text.startsWith("\uFEFF") ? text.slice(1) : text;
  const table = [];
  let row = [];
  let field = "";
  let quoted = false;
  let i = 0;
  const endF = () => { row.push(field); field = ""; };
  const endR = () => { endF(); table.push(row); row = []; };
  while (i < src.length) {
    const c = src[i];
    if (quoted) {
      if (c === '"') {
        if (src[i + 1] === '"') { field += '"'; i += 2; } else { quoted = false; i += 1; }
      } else { field += c; i += 1; }
    } else if (c === '"' && field === "") { quoted = true; i += 1; }
    else if (c === ",") { endF(); i += 1; }
    else if (c === "\r") { endR(); i += src[i + 1] === "\n" ? 2 : 1; }
    else if (c === "\n") { endR(); i += 1; }
    else { field += c; i += 1; }
  }
  if (quoted) throw new Error("DATA_UNREADABLE");
  if (field !== "" || row.length) endR();
  const clean = table.filter((r) => !(r.length === 1 && r[0] === ""));
  if (!clean.length) throw new Error("DATA_UNREADABLE");
  const header = clean[0];
  const rows = clean.slice(1).map((r) => {
    if (r.length !== header.length) throw new Error("DATA_UNREADABLE");
    const o = {};
    header.forEach((h, idx) => { o[h] = r[idx] === "" ? null : r[idx]; });
    return o;
  });
  return { fields: header, rows };
}

// JSON with numbers preserved verbatim as { n: "raw" } markers.
function parseJsonExact(text) {
  let i = 0;
  const bad = () => { throw new Error("DATA_UNREADABLE"); };
  const ws = () => { while (" \t\n\r".includes(text[i] ?? "")) i += 1; };
  function str() {
    let out = "";
    i += 1;
    while (i < text.length) {
      const c = text[i];
      if (c === '"') { i += 1; return out; }
      if (c === "\\") {
        const e = text[i + 1];
        if (e === "u") {
          const hex = text.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) bad();
          out += String.fromCharCode(parseInt(hex, 16));
          i += 6;
        } else {
          const map = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
          if (!(e in map)) bad();
          out += map[e];
          i += 2;
        }
      } else { out += c; i += 1; }
    }
    bad();
  }
  function num() {
    const start = i;
    if (text[i] === "-") i += 1;
    if (text[i] === "0") i += 1;
    else if (/[1-9]/.test(text[i] ?? "")) while (/[0-9]/.test(text[i] ?? "")) i += 1;
    else bad();
    if (text[i] === ".") {
      i += 1;
      if (!/[0-9]/.test(text[i] ?? "")) bad();
      while (/[0-9]/.test(text[i] ?? "")) i += 1;
    }
    if (text[i] === "e" || text[i] === "E") {
      i += 1;
      if (text[i] === "+" || text[i] === "-") i += 1;
      if (!/[0-9]/.test(text[i] ?? "")) bad();
      while (/[0-9]/.test(text[i] ?? "")) i += 1;
    }
    return { n: text.slice(start, i) };
  }
  function val() {
    ws();
    const c = text[i];
    if (c === "{") {
      i += 1;
      const o = {};
      ws();
      if (text[i] === "}") { i += 1; return o; }
      for (;;) {
        ws();
        if (text[i] !== '"') bad();
        const k = str();
        ws();
        if (text[i] !== ":") bad();
        i += 1;
        o[k] = val();
        ws();
        if (text[i] === ",") { i += 1; continue; }
        if (text[i] === "}") { i += 1; return o; }
        bad();
      }
    }
    if (c === "[") {
      i += 1;
      const a = [];
      ws();
      if (text[i] === "]") { i += 1; return a; }
      for (;;) {
        a.push(val());
        ws();
        if (text[i] === ",") { i += 1; continue; }
        if (text[i] === "]") { i += 1; return a; }
        bad();
      }
    }
    if (c === '"') return str();
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (text.startsWith("null", i)) { i += 4; return null; }
    return num();
  }
  const v = val();
  ws();
  if (i !== text.length) bad();
  return v;
}

const isNumCell = (v) => v !== null && typeof v === "object" && typeof v.n === "string";
function parseJsonl(text) {
  const src = text.startsWith("\uFEFF") ? text.slice(1) : text;
  const rows = [];
  for (const line of src.split(/\r?\n/)) {
    if (line.trim() === "") continue;
    const v = parseJsonExact(line);
    if (!v || typeof v !== "object" || Array.isArray(v) || isNumCell(v)) throw new Error("DATA_UNREADABLE");
    const o = {};
    for (const [k, cell] of Object.entries(v)) {
      if (cell !== null && typeof cell === "object" && !isNumCell(cell)) throw new Error("DATA_UNREADABLE");
      o[k] = cell === "" ? null : cell;
    }
    rows.push(o);
  }
  return { rows };
}

function loadRows(bytes, name) {
  const lower = name.toLowerCase();
  const text = bytes.toString("utf8");
  if (lower.endsWith(".csv")) return parseCsv(text).rows;
  if (lower.endsWith(".jsonl") || lower.endsWith(".ndjson")) return parseJsonl(text).rows;
  throw new Error("DATA_UNREADABLE");
}

// ---------------- replay compute (independent re-implementation) ----------------
function cellDec(v) {
  if (typeof v === "string") return parseDec(v);
  if (isNumCell(v)) return parseDec(v.n);
  return null;
}
function cellJson(v) {
  if (v === null || v === undefined) return null;
  if (isNumCell(v)) {
    const d = parseDec(v.n);
    return d ? canonDec(d) : v.n;
  }
  return v;
}
function cellId(v) {
  if (v === null || v === undefined) return "null";
  if (typeof v === "string") return `s:${v}`;
  if (typeof v === "boolean") return `b:${v}`;
  if (isNumCell(v)) {
    const d = parseDec(v.n);
    return `n:${d ? canonDec(d) : v.n}`;
  }
  return `s:${String(v)}`;
}
function codePointCmp(a, b) {
  const xa = Array.from(a);
  const xb = Array.from(b);
  const n = Math.min(xa.length, xb.length);
  for (let k = 0; k < n; k += 1) {
    const ca = xa[k].codePointAt(0);
    const cb = xb[k].codePointAt(0);
    if (ca !== cb) return ca < cb ? -1 : 1;
  }
  return xa.length === xb.length ? 0 : xa.length < xb.length ? -1 : 1;
}
function litDec(v) {
  if (typeof v === "string") return parseDec(v);
  if (isNumCell(v)) return parseDec(v.n);
  return null;
}
function cmpCell(cell, lit, field, idx, ordering) {
  if (typeof lit === "boolean") {
    return typeof cell === "boolean" && cell === lit ? 0 : null;
  }
  const dl = litDec(lit);
  const dc = cellDec(cell);
  if (dl && dc) return cmpDec(dc, dl);
  if (dl && !dc) {
    if (ordering) throw new Error(`NON_NUMERIC:${field}:${idx}`);
    return null;
  }
  if (typeof cell === "boolean" || typeof lit !== "string") return null;
  const cs = isNumCell(cell) ? cell.n : cell;
  if (typeof cs !== "string") return null;
  return codePointCmp(cs, lit);
}
function passesOne(row, f, idx) {
  const cell = row[f.field] ?? null;
  const op = f.operator ?? "eq";
  if (op === "is_null") return cell === null;
  if (op === "is_not_null") return cell !== null;
  if (cell === null) return false;
  if (op === "in" || op === "not_in") {
    const found = (Array.isArray(f.value) ? f.value : []).some(
      (v) => cmpCell(cell, v, f.field, idx, false) === 0
    );
    return op === "in" ? found : !found;
  }
  const ordering = ["gt", "gte", "lt", "lte"].includes(op);
  const c = cmpCell(cell, f.value, f.field, idx, ordering);
  if (op === "eq") return c === 0;
  if (op === "neq") return c !== 0;
  if (op === "gt") return c !== null && c > 0;
  if (op === "gte") return c !== null && c >= 0;
  if (op === "lt") return c !== null && c < 0;
  if (op === "lte") return c !== null && c <= 0;
  return false;
}
function numerics(entries, field) {
  const out = [];
  for (const e of entries) {
    const cell = e.row[field] ?? null;
    if (cell === null) continue;
    const d = cellDec(cell);
    if (!d) throw new Error(`NON_NUMERIC:${field}:${e.idx}`);
    out.push(d);
  }
  return out;
}
function sideValue(side, entries) {
  const es = (side.filters ?? []).length
    ? entries.filter((e) => side.filters.every((f) => passesOne(e.row, f, e.idx)))
    : entries;
  if (side.operation === "count") return { int: BigInt(es.length), scale: 0 };
  if (side.operation === "count_non_null") {
    return { int: BigInt(es.filter((e) => (e.row[side.field] ?? null) !== null).length), scale: 0 };
  }
  return sumDec(numerics(es, side.field));
}
function aggregate(def, entries) {
  const op = def.operation;
  const finish = (d) => ({ value: fmtDec(d), scale: d.scale });
  if (op === "count") return finish({ int: BigInt(entries.length), scale: 0 });
  if (op === "count_non_null") {
    return finish({ int: BigInt(entries.filter((e) => (e.row[def.field] ?? null) !== null).length), scale: 0 });
  }
  if (op === "count_distinct") {
    const seen = new Set();
    for (const e of entries) {
      const cell = e.row[def.field] ?? null;
      if (cell !== null) seen.add(cellId(cell));
    }
    return finish({ int: BigInt(seen.size), scale: 0 });
  }
  if (op === "sum") {
    const vs = numerics(entries, def.field);
    return finish(vs.length ? sumDec(vs) : { int: 0n, scale: 0 });
  }
  if (op === "min" || op === "max") {
    const vs = numerics(entries, def.field);
    if (!vs.length) throw new Error("EMPTY_DENOMINATOR_SET");
    let best = vs[0];
    for (const v of vs.slice(1)) {
      const c = cmpDec(v, best);
      if ((op === "min" && c < 0) || (op === "max" && c > 0)) best = v;
    }
    return finish(best);
  }
  if (op === "average") {
    const vs = numerics(entries, def.field);
    if (!vs.length) {
      if (ctx.allowEmptyPeriod) return { r: null, s: null, empty: true };
      throw new Error("EMPTY_DENOMINATOR_SET");
    }
    return finish(div12(sumDec(vs), { int: BigInt(vs.length), scale: 0 }));
  }
  if (op === "ratio") {
    return finish(div12(sideValue(def.numerator, entries), sideValue(def.denominator, entries)));
  }
  // A time-intelligence node over another one: the engine refuses it,
  // so the verifier refuses it too rather than inventing an answer.
  if (op === "ti") throw new Error("UNSUPPORTED_DEFINITION:OPERATION_TI");
  throw new Error(`UNSUPPORTED_OPERATION:${op}`);
}

// Exact rationals for expression replay: every intermediate value is
// an exact fraction; rounding happens at most once, at the very end.
function bgcd(a, b) {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b !== 0n) {
    const t = a % b;
    a = b;
    b = t;
  }
  return a;
}
function mkRat(num, den) {
  if (den === 0n) throw new Error("DIVIDE_BY_ZERO");
  const s = den < 0n ? -1n : 1n;
  const g = bgcd(num, den);
  return { n: (s * num) / g, d: (s * den) / g };
}
const intRat = (v) => ({ n: BigInt(v), d: 1n });
const decRat = (d) => mkRat(d.int, 10n ** BigInt(d.scale));
const ratAdd = (a, b) => mkRat(a.n * b.d + b.n * a.d, a.d * b.d);
const ratSub = (a, b) => mkRat(a.n * b.d - b.n * a.d, a.d * b.d);
const ratMul = (a, b) => mkRat(a.n * b.n, a.d * b.d);
const ratNeg = (a) => ({ n: -a.n, d: a.d });
function ratRound12(r) {
  const f = 10n ** 12n;
  const scaled = r.n * f;
  const neg = scaled < 0n;
  const abs = neg ? -scaled : scaled;
  let q = abs / r.d;
  const rem = abs % r.d;
  if (rem * 2n > r.d || (rem * 2n === r.d && q % 2n === 1n)) q += 1n;
  return { int: neg && q !== 0n ? -q : q, scale: 12 };
}
function ratNatural(r, scale) {
  const f = 10n ** BigInt(scale);
  const scaled = r.n * f;
  if (scaled % r.d !== 0n) throw new Error("REPLAY_INEXACT_NATURAL_SCALE");
  return { int: scaled / r.d, scale };
}

function opIsEmpty(op, field, entries) {
  if (op === "count") return entries.length === 0;
  return !entries.some((e) => (e.row[field] ?? null) !== null);
}
function sideIsEmpty(side, entries) {
  const es = (side.filters ?? []).length
    ? entries.filter((e) => side.filters.every((f) => passesOne(e.row, f, e.idx)))
    : entries;
  return opIsEmpty(side.operation, side.field, es);
}

// The rows of one window that also pass one filter set. A window is
// half-open [start, end) over one time field; a row with no value for
// that field is not in the window, and a value that is not a time
// refuses loudly rather than being dropped.
function rowsInWindow(rows, { timeField, start, end, filters }) {
  const matched = [];
  rows.forEach((row, idx) => {
    if (start !== null && end !== null) {
      const cell = row[timeField] ?? null;
      if (cell === null) return;
      const t = typeof cell === "string" ? parseInstant(cell) : null;
      if (t === null) throw new Error(`NON_TEMPORAL:${timeField}:${idx}`);
      if (t < start || t >= end) return;
    }
    if (!filters.every((f) => passesOne(row, f, idx))) return;
    matched.push({ row, idx });
  });
  return matched;
}

// The group key of one row.
function groupKeyOf(row, groupBy) {
  const key = {};
  for (const f of groupBy) key[f] = cellJson(row[f] ?? null);
  return key;
}

// The rows of one window that belong to one group. Every operand of
// an expression is evaluated over the same group keys, so a shifted
// operand contributes only its own group's rows.
function scopeToGroup(entries, groupBy, groupKey) {
  if (!groupBy.length || groupKey === null || groupKey === undefined) return entries;
  const wanted = canon(groupKey);
  return entries.filter((e) => canon(groupKeyOf(e.row, groupBy)) === wanted);
}

// The exact value of one definition over already-filtered entries.
function arithValueForDef(def, entries, ctx) {
  const op = def.operation;
  if (op === "arith") return arithEval(def.expr, def, entries, ctx);
  if (op === "count") return { r: intRat(entries.length), s: 0 };
  if (op === "count_non_null") {
    const n = entries.filter((e) => (e.row[def.field] ?? null) !== null).length;
    return { r: intRat(n), s: 0 };
  }
  if (op === "count_distinct") {
    const seen = new Set();
    for (const e of entries) {
      const c = e.row[def.field] ?? null;
      if (c !== null) seen.add(cellId(c));
    }
    return { r: intRat(seen.size), s: 0 };
  }
  if (op === "sum") {
    const vs = numerics(entries, def.field);
    if (!vs.length) return { r: intRat(0), s: 0, empty: true };
    const t = sumDec(vs);
    return { r: decRat(t), s: t.scale };
  }
  if (op === "min" || op === "max") {
    const vs = numerics(entries, def.field);
    if (!vs.length) {
      // Inside a SET of periods an empty period is an empty cell, not
      // an error (FROGA V1.3 P2).
      if (ctx.allowEmptyPeriod) return { r: null, s: null, empty: true };
      throw new Error("EMPTY_DENOMINATOR_SET");
    }
    let best = vs[0];
    for (const v of vs.slice(1)) {
      const c = cmpDec(v, best);
      if ((op === "min" && c < 0) || (op === "max" && c > 0)) best = v;
    }
    return { r: decRat(best), s: best.scale };
  }
  if (op === "average") {
    const vs = numerics(entries, def.field);
    if (!vs.length) {
      if (ctx.allowEmptyPeriod) return { r: null, s: null, empty: true };
      throw new Error("EMPTY_DENOMINATOR_SET");
    }
    const t = sumDec(vs);
    return { r: mkRat(t.int, BigInt(vs.length) * 10n ** BigInt(t.scale)), s: 12 };
  }
  if (op === "ratio") {
    // Exact rational of the two side aggregates — never the rounded
    // V1 value (spec §3.4: nothing rounded before the final step).
    const n = decRat(sideValue(def.numerator, entries));
    const dv = decRat(sideValue(def.denominator, entries));
    if (dv.n === 0n) throw new Error("DIVIDE_BY_ZERO");
    return { r: mkRat(n.n * dv.d, n.d * dv.n), s: 12 };
  }
  throw new Error(`UNSUPPORTED_OPERATION:${op}`);
}

// The aggregate of a set of periods: MDX semantics. A SUM adds the
// periods; an AVERAGE is over the NON-EMPTY periods only, and is null
// when every period is empty.
function tiAggregateSet(aggregate, values) {
  if (aggregate === "sum") {
    let total = null;
    let scale = 0;
    for (const value of values) {
      if (value.r === null) continue;
      total = total === null ? value.r : ratAdd(total, value.r);
      if (value.s > scale) scale = value.s;
    }
    if (total === null) return { r: intRat(0), s: 0, empty: true };
    return { r: total, s: scale };
  }
  const present = values.filter((value) => value.r !== null && !value.empty);
  if (!present.length) return { r: null, s: null, empty: true };
  let total = null;
  for (const value of present) {
    total = total === null ? value.r : ratAdd(total, value.r);
  }
  return { r: mkRat(total.n, total.d * BigInt(present.length)), s: 12 };
}

// The final rendering of a set's aggregate: an average is rounded at
// scale 12 at the very end, and a sum keeps its natural scale.
function tiFormatSetValue(aggregate, value) {
  if (value.r === null) return { value: null, scale: null };
  if (aggregate === "avg") {
    const d = ratRound12(value.r);
    return { value: fmtDec(d), scale: 12 };
  }
  const d = ratNatural(value.r, value.s);
  return { value: fmtDec(d), scale: value.s };
}

// The value of a SET of periods: the base read over each period, and
// the periods aggregated. An empty period is an empty cell, not an
// error, so the base's own aggregation may come back empty.
function tiSetValue(ti, baseIr, baseDef, ctx, filters) {
  const windows = tiWindowsOf(ti, ctx.askWindow, ctx.askPeriod);
  const values = [];
  for (const bounds of windows) {
    const rows = rowsInWindow(ctx.rows, {
      timeField: baseIr.time_field,
      start: bounds.start,
      end: bounds.end,
      filters
    });
    const scoped = scopeToGroup(rows, ctx.groupBy, ctx.groupKey);
    values.push(arithValueForDef(baseDef, scoped, { ...ctx, allowEmptyPeriod: true }));
  }
  return tiAggregateSet(ti.aggregate, values);
}

// One operand's value. A time-intelligence operand reads its base
// over its OWN window (a shifted or a to-date one), so it re-reads the
// rows rather than using the entries it was handed: the base is read
// with the base's filters, the time-intelligence node's filters, the
// per-use filters and the filters that apply everywhere.
function arithOperand(ir, entries, ctx, operand = null) {
  const def = ir.definition;
  if (def.operation === "ti") {
    const baseIr = tiBaseIr(def, ctx.inputs, ir);
    if (!baseIr) throw new Error("REPLAY_INPUT_MISSING");
    if (!baseIr.time_field) throw new Error("NO_TIME_FIELD");
    const baseDef = baseIr.definition;
    const filters = [
      ...(operand?.filters ?? []),
      ...(def.filters ?? []),
      ...(baseDef.filters ?? []),
      ...ctx.allFilters
    ];
    if (def.kind === "member_set") {
      return tiSetValue(def, baseIr, baseDef, ctx, filters);
    }
    const bounds = def.kind === "member_nav"
      ? tiWindowsOf(def, ctx.askWindow, ctx.askPeriod)[0]
      : tiWindowFor(def, ctx.askWindow);
    const rows = rowsInWindow(ctx.rows, {
      timeField: baseIr.time_field,
      start: bounds.start,
      end: bounds.end,
      filters
    });
    return arithValueForDef(baseDef, scopeToGroup(rows, ctx.groupBy, ctx.groupKey), ctx);
  }
  // An operand that carries a set of periods reads the base over each
  // of them and aggregates: a set is not "the rows of one window".
  if (operand?.ti?.kind === "member_set") {
    if (!ir.time_field) throw new Error("NO_TIME_FIELD");
    const filters = [...(operand.filters ?? []), ...(def.filters ?? []), ...ctx.allFilters];
    return tiSetValue(operand.ti, ir, def, ctx, filters);
  }
  return arithValueForDef(def, entries, ctx);
}

// The entries one operand reference contributes. Three shapes:
//
//   - an operand that carries its own shift reads a DIFFERENT window,
//     so its rows are re-read from the raw rows;
//   - an operand that points at a time-intelligence metric is re-read
//     inside arithOperand, which knows the base's filters; here only
//     the per-use filters apply;
//   - anything else takes the entries of the ask window, filtered by
//     the per-use filters and the input's own definition filters.
function arithRefEntries(def, name, entries, ctx) {
  const operand = def.operands[name];
  const ir = ctx.inputs[operand.object_id];
  if (!ir) throw new Error("REPLAY_INPUT_MISSING");
  const ownDef = ir.definition;
  if (operand.ti) {
    // A SET of periods is not "the rows of one window": it is an
    // aggregate over several, and it is computed in arithOperand.
    if (operand.ti.kind === "member_set") {
      const all = [...(operand.filters ?? []), ...(ownDef.filters ?? [])];
      return all.length ? entries.filter((e) => all.every((f) => passesOne(e.row, f, e.idx))) : entries;
    }
    if (!ir.time_field) throw new Error("NO_TIME_FIELD");
    // A member NAVIGATION reads the period relative to the CURRENT MEMBER,
    // so it needs the Ask's period; a shift or a to-date reads the Ask's
    // window as it is.
    const bounds = operand.ti.kind === "member_nav"
      ? tiWindowsOf(operand.ti, ctx.askWindow, ctx.askPeriod)[0]
      : tiWindowFor(operand.ti, ctx.askWindow);
    const filters = [...(operand.filters ?? []), ...(ownDef.filters ?? []), ...ctx.allFilters];
    const rows = rowsInWindow(ctx.rows, {
      timeField: ir.time_field,
      start: bounds.start,
      end: bounds.end,
      filters
    });
    return scopeToGroup(rows, ctx.groupBy, ctx.groupKey);
  }
  if (ownDef.operation === "ti") {
    const filters = operand.filters ?? [];
    return filters.length ? entries.filter((e) => filters.every((f) => passesOne(e.row, f, e.idx))) : entries;
  }
  const all = [...(operand.filters ?? []), ...(ownDef.filters ?? [])];
  return all.length ? entries.filter((e) => all.every((f) => passesOne(e.row, f, e.idx))) : entries;
}

// ISEMPTY(name): true when the operand has no contributing non-null
// value in its filtered entries. A time-intelligence operand is empty
// when its own window holds nothing.
function arithIsEmpty(name, def, entries, ctx) {
  const operand = def.operands[name];
  const ir = ctx.inputs[operand.object_id];
  if (!ir) throw new Error("REPLAY_INPUT_MISSING");
  const d = ir.definition;
  if (d.operation === "ti") {
    const baseIr = tiBaseIr(d, ctx.inputs, ir);
    if (!baseIr) throw new Error("REPLAY_INPUT_MISSING");
    if (!baseIr.time_field) throw new Error("NO_TIME_FIELD");
    const baseDef = baseIr.definition;
    const filters = [
      ...(operand.filters ?? []),
      ...(d.filters ?? []),
      ...(baseDef.filters ?? []),
      ...ctx.allFilters
    ];
    if (d.kind === "member_set") {
      const value = tiSetValue(d, baseIr, baseDef, ctx, filters);
      return value.r === null || value.empty === true;
    }
    const bounds = d.kind === "member_nav"
      ? tiWindowsOf(d, ctx.askWindow, ctx.askPeriod)[0]
      : tiWindowFor(d, ctx.askWindow);
    const rows = rowsInWindow(ctx.rows, {
      timeField: baseIr.time_field,
      start: bounds.start,
      end: bounds.end,
      filters
    });
    return isEmptyForDef(baseDef, scopeToGroup(rows, ctx.groupBy, ctx.groupKey), ctx);
  }
  return isEmptyForDef(d, arithRefEntries(def, name, entries, ctx), ctx);
}
function isEmptyForDef(def, entries, ctx) {
  if (def.operation === "arith") return arithEval(def.expr, def, entries, ctx).r === null;
  if (def.operation === "ratio") {
    return sideIsEmpty(def.numerator, entries) || sideIsEmpty(def.denominator, entries);
  }
  return opIsEmpty(def.operation, def.field, entries);
}
function arithEval(node, def, entries, ctx) {
  if (typeof node.ref === "string") {
    const operand = def.operands[node.ref];
    const ir = ctx.inputs[operand.object_id];
    if (!ir) throw new Error("REPLAY_INPUT_MISSING");
    return arithOperand(ir, arithRefEntries(def, node.ref, entries, ctx), ctx, operand);
  }
  if (typeof node.lit === "string") {
    const d = parseDec(node.lit);
    if (!d) throw new Error("REPLAY_BAD_LITERAL");
    return { r: decRat(d), s: d.scale };
  }
  if (node.op === "neg") {
    const v = arithEval(node.args[0], def, entries, ctx);
    return v.r === null ? v : { r: ratNeg(v.r), s: v.s };
  }
  if (node.op === "+" || node.op === "-") {
    const a = arithEval(node.args[0], def, entries, ctx);
    const b = arithEval(node.args[1], def, entries, ctx);
    if (a.r === null || b.r === null) return { r: null, s: null };
    return { r: node.op === "+" ? ratAdd(a.r, b.r) : ratSub(a.r, b.r), s: Math.max(a.s, b.s) };
  }
  if (node.op === "*") {
    const a = arithEval(node.args[0], def, entries, ctx);
    const b = arithEval(node.args[1], def, entries, ctx);
    if (a.r === null || b.r === null) return { r: null, s: null };
    return { r: ratMul(a.r, b.r), s: a.s + b.s };
  }
  if (node.op === "/") {
    const a = arithEval(node.args[0], def, entries, ctx);
    const b = arithEval(node.args[1], def, entries, ctx);
    if (a.r === null || b.r === null) return { r: null, s: null };
    if (b.r.n === 0n) throw new Error("DIVIDE_BY_ZERO");
    return { r: mkRat(a.r.n * b.r.d, a.r.d * b.r.n), s: 12 };
  }
  if (node.op === "null_if_empty") {
    for (const name of node.guards) {
      if (arithIsEmpty(name, def, entries, ctx)) return { r: null, s: null };
    }
    return arithEval(node.then, def, entries, ctx);
  }
  if (node.op === "zero_if_empty") {
    // An empty cell is zero, exactly: the MDX IIF(IsEmpty(<cell>), 0,
    // <cell>) shape (FROGA V1.3 P3).
    for (const name of node.guards) {
      if (arithIsEmpty(name, def, entries, ctx)) return { r: intRat(0), s: 0 };
    }
    return arithEval(node.then, def, entries, ctx);
  }
  throw new Error("REPLAY_BAD_NODE");
}
function astHasDiv(node) {
  if (!node || typeof node !== "object") return false;
  if (node.op === "/") return true;
  if (Array.isArray(node.args) && node.args.some(astHasDiv)) return true;
  return node.then !== undefined && astHasDiv(node.then);
}
function arithFinalScale12(def, defs) {
  if (astHasDiv(def.expr)) return true;
  // An AVERAGE over a SET of periods is a division: the mean of the
  // non-empty periods is rounded only at the very end (scale 12,
  // HALF_EVEN).
  for (const operand of Object.values(def.operands ?? {})) {
    if (operand.ti?.kind === "member_set" && operand.ti.aggregate === "avg") return true;
  }
  for (const id of Object.keys(defs)) {
    const d = defs[id].definition;
    const op = d.operation;
    if (op === "average" || op === "ratio") return true;
    if (op === "arith" && astHasDiv(d.expr)) return true;
    if (op === "ti" && d.kind === "member_set" && d.aggregate === "avg") return true;
  }
  return false;
}
function arithGroup(def, entries, ctx) {
  const v = arithEval(def.expr, def, entries, ctx);
  if (v.r === null) return { value: null, scale: null };
  if (arithFinalScale12(def, ctx.inputs)) {
    const d = ratRound12(v.r);
    return { value: fmtDec(d), scale: 12 };
  }
  const d = ratNatural(v.r, v.s);
  return { value: fmtDec(d), scale: v.s };
}

// Recompute an answer from the recorded question, the recorded
// definitions and the raw rows.
//
// A time-intelligence ROOT reads its BASE over a shifted or to-date
// window, over the BASE's time field and with the BASE's definition;
// the base's filters, the time-intelligence node's filters and the
// question's filters all apply. Everything else reads the ask window
// over the ask's own time field, as before.
function replayAnswer(ir, question, rows, inputDefs = null) {
  const def = ir.definition;
  const timeField = ir.time_field ?? null;
  const window = question.window ?? null;
  const groupBy = question.group_by ?? [];
  const questionFilters = question.filters ?? [];
  const allFilters = [...(def.filters ?? []), ...questionFilters];
  let start = null;
  let end = null;
  if (window) {
    start = parseInstant(window.start);
    end = parseInstant(window.end);
    if (start === null || end === null) throw new Error("BAD_WINDOW");
  }
  const ctx = {
    rows,
    inputs: inputDefs ?? {},
    askWindow: window,
    askPeriod: question.period ?? null,
    allFilters,
    groupBy,
    groupKey: null
  };
  // A SET of periods is an aggregate over SEVERAL windows, so it does
  // not go through the one-window path below.
  if (def.operation === "ti" && def.kind === "member_set") {
    return tiSetRoot(def, ir, ctx, groupBy);
  }
  let rootDef = def;
  let matched;
  if (def.operation === "ti") {
    const baseIr = tiBaseIr(def, ctx.inputs, ir);
    if (!baseIr) throw new Error("REPLAY_INPUT_MISSING");
    if (!baseIr.time_field) throw new Error("NO_TIME_FIELD");
    const baseDef = baseIr.definition;
    const bounds = def.kind === "member_nav"
      ? tiWindowsOf(def, window, ctx.askPeriod)[0]
      : tiWindowFor(def, window);
    rootDef = baseDef;
    matched = rowsInWindow(rows, {
      timeField: baseIr.time_field,
      start: bounds.start,
      end: bounds.end,
      filters: [...(def.filters ?? []), ...(baseDef.filters ?? []), ...questionFilters]
    });
  } else {
    // An expression reads over the column its inputs agree on: its own
    // time field when it has one, the inherited one when it does not.
    matched = rowsInWindow(rows, {
      timeField: effectiveTimeField(ir, ctx.inputs) ?? timeField,
      start,
      end,
      filters: allFilters
    });
  }
  const groups = new Map();
  if (!groupBy.length) {
    groups.set("{}", { key: {}, entries: matched });
  } else {
    for (const e of matched) {
      const key = groupKeyOf(e.row, groupBy);
      const id = canon(key);
      if (!groups.has(id)) groups.set(id, { key, entries: [] });
      groups.get(id).entries.push(e);
    }
  }
  const keyCmp = (a, b) => {
    for (const f of groupBy) {
      const av = a[f];
      const bv = b[f];
      if (av === null && bv === null) continue;
      if (av === null) return -1;
      if (bv === null) return 1;
      const ca = canon(av);
      const cb = canon(bv);
      if (ca !== cb) return ca < cb ? -1 : 1;
    }
    const ja = canon(a);
    const jb = canon(b);
    return ja === jb ? 0 : ja < jb ? -1 : 1;
  };
  const perGroup = rootDef.operation === "arith"
    ? (() => {
      if (!inputDefs) throw new Error("REPLAY_INPUT_MISSING");
      return (g) => ({ key: g.key, ...arithGroup(rootDef, g.entries, { ...ctx, groupKey: g.key }) });
    })()
    : (g) => ({ key: g.key, ...aggregate(rootDef, g.entries) });
  const out = [...groups.values()]
    .sort((x, y) => keyCmp(x.key, y.key))
    .map(perGroup);
  return { groups: out, rows_scanned: rows.length, rows_matched: matched.length };
}

// The answer for a SET of periods: the base read over each period, and
// the periods aggregated, per group. The groups are the union of the
// groups of every period.
function tiSetRoot(def, ir, ctx, groupBy) {
  const baseIr = tiBaseIr(def, ctx.inputs, ir);
  if (!baseIr) throw new Error("REPLAY_INPUT_MISSING");
  if (!baseIr.time_field) throw new Error("NO_TIME_FIELD");
  const baseDef = baseIr.definition;
  const filters = [...(def.filters ?? []), ...(baseDef.filters ?? []), ...ctx.allFilters];
  const windows = tiWindowsOf(def, ctx.askWindow, ctx.askPeriod);
  const byGroup = new Map();
  let rowsMatched = 0;
  for (const bounds of windows) {
    const rows = rowsInWindow(ctx.rows, {
      timeField: baseIr.time_field,
      start: bounds.start,
      end: bounds.end,
      filters
    });
    rowsMatched += rows.length;
    const grouped = new Map();
    if (!groupBy.length) {
      grouped.set("{}", { key: {}, entries: rows });
    } else {
      for (const e of rows) {
        const key = groupKeyOf(e.row, groupBy);
        const id = canon(key);
        if (!grouped.has(id)) grouped.set(id, { key, entries: [] });
        grouped.get(id).entries.push(e);
      }
    }
    for (const [id, group] of grouped) {
      if (!byGroup.has(id)) byGroup.set(id, { key: group.key, values: [] });
      byGroup.get(id).values.push(
        arithValueForDef(baseDef, group.entries, { ...ctx, allowEmptyPeriod: true })
      );
    }
  }
  const keyCmp = (a, b) => {
    for (const f of groupBy) {
      const av = a[f];
      const bv = b[f];
      if (av === null && bv === null) continue;
      if (av === null) return -1;
      if (bv === null) return 1;
      const ca = canon(av);
      const cb = canon(bv);
      if (ca !== cb) return ca < cb ? -1 : 1;
    }
    const ja = canon(a);
    const jb = canon(b);
    return ja === jb ? 0 : ja < jb ? -1 : 1;
  };
  const out = [...byGroup.values()]
    .sort((x, y) => keyCmp(x.key, y.key))
    .map((g) => ({
      key: g.key,
      ...tiFormatSetValue(def.aggregate, tiAggregateSet(def.aggregate, g.values))
    }));
  return { groups: out, rows_scanned: ctx.rows.length, rows_matched: rowsMatched };
}

// ---------------- ledger verification ----------------
function verifyReceiptHash(receipt) {
  if (!receipt || receipt.receipt_version !== "jl.receipt.v1") {
    return "UNSUPPORTED_RECEIPT_VERSION";
  }
  const { receipt_hash: claimed, ...body } = receipt;
  let actual;
  try {
    actual = addr(body);
  } catch {
    return "RECEIPT_NOT_CANONICAL";
  }
  return claimed === actual ? null : "RECEIPT_HASH_MISMATCH";
}

// The entry hash binds the entry to its place in the chain: version,
// sequence, receipt, receipt hash and the previous entry's hash.
function entryHashOf(e) {
  return addr({
    entry_version: e.entry_version,
    seq: e.seq,
    receipt: e.receipt,
    receipt_hash: e.receipt_hash,
    previous_entry_hash: e.previous_entry_hash ?? null
  });
}

// Check one seal's signature against a public key. Returns null when the
// signature is good, otherwise the reason. Shared by the ledger path and
// the proof-packet path so the two never drift apart.
function sealSignatureProblem(seal, pubkeyPem) {
  const approval = seal?.approval ?? {};
  if (approval.protocol !== "jl.semantic-authority.v1") return "UNSUPPORTED_PROTOCOL";
  if (approval.purpose !== "mantle-receipts-seal") return "PURPOSE_MISMATCH";
  if (approval.target_hash !== addr(seal.target ?? {})) return "TARGET_HASH_MISMATCH";
  if (approval.public_key_fingerprint !== `sha256:${sha256hex(pubkeyPem)}`) {
    return "KEY_FINGERPRINT_MISMATCH";
  }
  const payload = {
    protocol: approval.protocol,
    actor: approval.actor,
    purpose: approval.purpose,
    target_hash: approval.target_hash
  };
  let ok = false;
  try {
    ok = cryptoVerify(null, Buffer.from(canon(payload)), pubkeyPem, Buffer.from(approval.signature, "base64"));
  } catch {
    ok = false;
  }
  return ok ? null : "SIGNATURE_INVALID";
}

function verifyLedger(ledgerPath, { pubkeyPath = null, replay = null } = {}) {
  let text;
  try {
    text = readFileSync(ledgerPath, "utf8");
  } catch {
    return { valid: false, length: 0, head: null, chain_hash: null, seals_checked: 0, seal_signatures_verified: 0, replayed: 0, errors: [{ index: -1, reason: "LEDGER_UNREADABLE" }] };
  }
  const lines = text.split("\n").filter((l) => l !== "");
  const errors = [];
  const entries = [];
  lines.forEach((line, index) => {
    let env;
    try {
      env = JSON.parse(line);
    } catch {
      errors.push({ index, reason: "LINE_NOT_JSON" });
      return;
    }
    entries.push(env);
    if (env?.entry_version !== "jl.mantle-ledger.v1") {
      errors.push({ index, reason: "UNSUPPORTED_ENTRY_VERSION" });
      return;
    }
    const receipt = env.receipt ?? {};
    if (env.seq !== index) errors.push({ index, reason: "SEQ_MISMATCH" });
    const expectedPrev = index === 0 ? null : entries[index - 1]?.entry_hash ?? null;
    if ((env.previous_entry_hash ?? null) !== expectedPrev) {
      errors.push({ index, reason: "PREVIOUS_ENTRY_HASH_MISMATCH" });
    }
    try {
      if (env.entry_hash !== entryHashOf(env)) errors.push({ index, reason: "ENTRY_HASH_MISMATCH" });
    } catch {
      errors.push({ index, reason: "ENTRY_NOT_CANONICAL" });
    }
    if (env.receipt_hash !== receipt.receipt_hash) {
      errors.push({ index, reason: "ENTRY_RECEIPT_HASH_MISMATCH" });
    }
    const hashProblem = verifyReceiptHash(receipt);
    if (hashProblem) errors.push({ index, reason: hashProblem });
    try {
      if (addr(env.input ?? null) !== receipt.input_hash) errors.push({ index, reason: "INPUT_HASH_MISMATCH" });
      if (addr(env.output ?? null) !== receipt.output_hash) errors.push({ index, reason: "OUTPUT_HASH_MISMATCH" });
      const evHashes = (env.evidence ?? []).map((e) => addr(e)).sort();
      if (canon(evHashes) !== canon(receipt.evidence_hashes ?? [])) {
        errors.push({ index, reason: "EVIDENCE_HASH_MISMATCH" });
      }
      (env.evidence ?? []).forEach((e, i) => {
        const p = verifyReceiptHash(e);
        if (p) errors.push({ index, reason: `EVIDENCE_RECEIPT_INVALID:${i}:${p}` });
      });
    } catch {
      errors.push({ index, reason: "ENTRY_NOT_CANONICAL" });
    }
  });
  const head = entries.at(-1)?.entry_hash ?? null;
  const chainHash = sha256hex(canon(entries.map((e) => e.entry_hash ?? null)));

  // Seals (beside the ledger). Seal structure, targets and length are
  // always checked; cryptographic signatures only when --pubkey is given.
  let sealsChecked = 0;
  let sealSignaturesVerified = 0;
  let pubkeyPem = null;
  if (pubkeyPath) {
    try {
      pubkeyPem = readFileSync(pubkeyPath, "utf8");
    } catch {
      errors.push({ index: -1, reason: "PUBKEY_UNREADABLE" });
    }
  }
  const sealsPath = join(dirname(ledgerPath), "seals.jsonl");
  if (existsSync(sealsPath)) {
    let sealLines = null;
    try {
      sealLines = readFileSync(sealsPath, "utf8").split("\n").filter((l) => l !== "");
      sealLines.forEach((line) => JSON.parse(line));
    } catch {
      sealLines = null;
    }
    if (sealLines === null) {
      errors.push({ index: -1, reason: "SEALS_UNREADABLE" });
    } else sealLines.forEach((line, sealIndex) => {
      sealsChecked += 1;
      const seal = JSON.parse(line);
      const target = seal.target ?? {};
      const len = target.length;
      if (!Number.isInteger(len) || len < 0 || len > entries.length) {
        errors.push({ index: -1, reason: `SEAL_${sealIndex}_LENGTH_OUT_OF_RANGE` });
        return;
      }
      const prefixHead = len === 0 ? null : entries[len - 1].entry_hash;
      const prefixChain = sha256hex(canon(entries.slice(0, len).map((e) => e.entry_hash ?? null)));
      if (prefixHead !== target.ledger_head || prefixChain !== target.chain_hash) {
        errors.push({ index: -1, reason: `SEAL_${sealIndex}_TARGET_MISMATCH` });
        return;
      }
      if (!pubkeyPem) return;
      const problem = sealSignatureProblem(seal, pubkeyPem);
      if (problem) errors.push({ index: -1, reason: `SEAL_${sealIndex}_${problem}` });
      else sealSignaturesVerified += 1;
    });
  }

  // Replay: re-run every CERTIFIED Ask from its recorded inputs with the
  // independent compute above, over data files whose bytes must hash to
  // the recorded data hash.
  let replayed = 0;
  if (replay) {
    entries.forEach((env, index) => {
      if (env?.receipt?.operation !== "ask") return;
      if (env?.output?.verdict !== "CERTIFIED") return;
      replayed += 1;
      const ir = env.input?.meaning_ir;
      const question = env.input?.question;
      const dataInfo = env.output?.data;
      if (!ir || !question || !dataInfo?.name) {
        errors.push({ index, reason: "REPLAY_INPUT_MISSING" });
        return;
      }
      const candidates = [
        join(replay.dataDir, dataInfo.name),
        join(replay.repo, dataInfo.name),
        join(dirname(ledgerPath), dataInfo.name)
      ];
      const found = candidates.find((p) => existsSync(p));
      if (!found) {
        errors.push({ index, reason: `REPLAY_DATA_NOT_FOUND:${dataInfo.name}` });
        return;
      }
      const bytes = readFileSync(found);
      if (sha256hex(bytes) !== dataInfo.sha256) {
        errors.push({ index, reason: "REPLAY_DATA_HASH_MISMATCH" });
        return;
      }
      // Expression asks must record every resolved input IR; the
      // verifier replays from those and re-checks dataset agreement.
      // A time-intelligence ask records its base the same way.
      const inputDefs = env.input?.input_defs ?? null;
      const usesInputs =
        ir.definition?.operation === "arith" || ir.definition?.operation === "ti";
      if (usesInputs) {
        const listed = env.output?.meaning?.inputs ?? [];
        const missing = listed.some((m) => !inputDefs || !(m.object_id in inputDefs));
        if (missing || !inputDefs) {
          errors.push({ index, reason: "REPLAY_INPUT_MISSING" });
          return;
        }
        const datasets = new Set();
        for (const id of Object.keys(inputDefs)) {
          const op = inputDefs[id].definition?.operation;
          if (op === "arith") continue;
          datasets.add(inputDefs[id].scope?.dataset ?? null);
        }
        if (datasets.size > 1) {
          errors.push({ index, reason: "REPLAY_DATASET_MISMATCH" });
          return;
        }
      }
      let result;
      let tiWindows;
      try {
        const dataRows = loadRows(bytes, dataInfo.name);
        result = replayAnswer(ir, question, dataRows, inputDefs);
        tiWindows = tiWindowsFor(ir.definition, inputDefs ?? {}, question.window ?? null, question.period ?? null);
      } catch (error) {
        errors.push({ index, reason: `REPLAY_COMPUTE_FAILED:${error.message}` });
        return;
      }
      if (canon(result.groups) !== canon(env.output.answer?.groups ?? null)) {
        errors.push({ index, reason: "REPLAY_ANSWER_MISMATCH" });
        return;
      }
      if (result.rows_scanned !== dataInfo.rows_scanned || result.rows_matched !== dataInfo.rows_matched) {
        errors.push({ index, reason: "REPLAY_ROW_COUNT_MISMATCH" });
      }
      // The windows a time-intelligence answer actually read over are
      // part of the claim, so they are recomputed here as well.
      if (canon(tiWindows) !== canon(env.output.ti_windows ?? [])) {
        errors.push({ index, reason: "REPLAY_TI_WINDOW_MISMATCH" });
      }
    });
  }

  return {
    valid: errors.length === 0,
    length: entries.length,
    head,
    chain_hash: chainHash,
    seals_checked: sealsChecked,
    seal_signatures_verified: sealSignaturesVerified,
    replayed,
    errors
  };
}

// ---------------- proof packet verification (FROGA V1.2-a) ----------------
//
// A proof packet is one file an auditor can check without trusting us.
// The checks run in order and the FIRST failure decides the exit code:
// nothing later is assumed about anything earlier.
const PACKET_VERSION = "jl.froga-proof-packet.v1";

function fail(check, reason, detail) {
  return { check, reason, ...(detail === undefined ? {} : { detail }) };
}

// -- structural hash, re-implemented from the meaning, not shared -------
function normalizeFilter(filter) {
  return {
    field: filter?.field,
    operator: filter?.operator ?? "eq",
    value: filter?.value === undefined ? null : filter.value
  };
}
function normalizeSide(side) {
  if (!side || typeof side !== "object") return side;
  return {
    operation: side.operation,
    field: side.field ?? null,
    filters: (side.filters ?? []).map(normalizeFilter)
  };
}
function normalizeExpr(node) {
  if (!node || typeof node !== "object" || Array.isArray(node)) return node;
  if (typeof node.ref === "string") return { ref: node.ref };
  if (typeof node.lit === "string") return { lit: node.lit };
  if (node.op === "null_if_empty" || node.op === "zero_if_empty") {
    return {
      op: node.op,
      guards: Array.isArray(node.guards) ? [...node.guards] : [],
      then: normalizeExpr(node.then)
    };
  }
  if (typeof node.op === "string" && Array.isArray(node.args)) {
    return { op: node.op, args: node.args.map(normalizeExpr) };
  }
  return node;
}
// A time-intelligence node, normalized. `n` rides on a shift and on a
// day offset; a to-date node has no count of periods. A day offset
// carries a unit instead of a grain.
//
// A member navigation and a member set (FROGA V1.3 P2) carry their own
// members: the navigation and the grains the hierarchy has levels for,
// and the set and how it is aggregated.
function normalizeTI(ti) {
  if (!ti || typeof ti !== "object") return ti;
  const kind = ti.kind ?? null;
  const grain = ti.grain ?? null;
  if (kind === "shift") return { kind, grain, n: ti.n ?? null };
  if (kind === "day_offset") return { kind, unit: ti.unit ?? null, n: ti.n ?? null };
  if (kind === "member_nav") {
    return {
      kind,
      nav: {
        type: ti.nav?.type ?? null,
        n: ti.nav?.n ?? null,
        grain: ti.nav?.grain ?? null
      },
      grains: [...new Set((ti.grains ?? []).filter((g) => typeof g === "string" && g))].sort()
    };
  }
  if (kind === "member_set") {
    return {
      kind,
      set: {
        type: ti.set?.type ?? null,
        from: ti.set?.from ?? null,
        to: ti.set?.to ?? null,
        level: ti.set?.level ?? null,
        grain: ti.set?.grain ?? null
      },
      aggregate: ti.aggregate ?? null,
      grains: [...new Set((ti.grains ?? []).filter((g) => typeof g === "string" && g))].sort()
    };
  }
  return { kind, grain };
}
// A time-intelligence base is either a metric — named by object_id — or,
// when the reading is of a measure rather than of a metric, its own
// definition. The metric form keeps its exact bytes.
function normalizeTiBase(base) {
  if (typeof base?.object_id === "string" && base.object_id) {
    return { object_id: base.object_id };
  }
  if (base?.definition && typeof base.definition === "object" && !Array.isArray(base.definition)) {
    return { definition: normalizeDefinition(base.definition) };
  }
  return { object_id: null };
}

// The base a time-intelligence node reads: the metric it names, or — for
// a reading of a measure rather than of a metric — its own definition,
// read over the node's own time field.
function tiBaseIr(def, inputs, nodeIr) {
  const base = def?.base ?? null;
  if (typeof base?.object_id === "string" && base.object_id) {
    return inputs?.[base.object_id] ?? null;
  }
  if (base?.definition && typeof base.definition === "object" && !Array.isArray(base.definition)) {
    return {
      time_field: nodeIr?.time_field ?? null,
      definition: base.definition,
      scope: nodeIr?.scope ?? null
    };
  }
  return null;
}

// The column a definition is actually read over: its own, or — for a
// definition that has none of its own — the one its inputs agree on. Only
// the time-intelligence BASE needs a time field of its own; the expression
// and guard wrappers around it must not demand their own.
function effectiveTimeField(ir, inputs) {
  if (!ir || typeof ir !== "object") return null;
  if (ir.time_field) return ir.time_field;
  const def = ir.definition;
  if (!def || typeof def !== "object") return null;
  if (def.operation === "ti") {
    const base = tiBaseIr(def, inputs, ir);
    return base ? effectiveTimeField(base, inputs) : null;
  }
  if (def.operation === "arith") {
    const fields = new Set();
    for (const name of Object.keys(def.operands ?? {}).sort()) {
      const operand = def.operands[name];
      const input = inputs?.[operand.object_id] ?? null;
      const field = effectiveTimeField(input, inputs);
      if (field) fields.add(field);
    }
    return fields.size === 1 ? [...fields][0] : null;
  }
  return null;
}

function normalizeDefinition(def) {
  if (!def || typeof def !== "object") return def;
  if (def.operation === "arith") {
    const operands = {};
    for (const [name, operand] of Object.entries(def.operands ?? {})) {
      const normalized = {
        object_id: operand.object_id,
        filters: (operand.filters ?? []).map(normalizeFilter)
      };
      // An operand may itself be shifted. The key is present only when
      // there is one, so every V1 operand keeps its exact shape and its
      // structural hash does not move.
      if (operand.ti !== undefined && operand.ti !== null) {
        normalized.ti = normalizeTI(operand.ti);
      }
      operands[name] = normalized;
    }
    return {
      operation: "arith",
      operands,
      expr: normalizeExpr(def.expr),
      filters: (def.filters ?? []).map(normalizeFilter)
    };
  }
  if (def.operation === "ratio") {
    return {
      operation: "ratio",
      numerator: normalizeSide(def.numerator),
      denominator: normalizeSide(def.denominator),
      filters: (def.filters ?? []).map(normalizeFilter)
    };
  }
  // A time-intelligence definition: the base metric, read over a
  // shifted or to-date window. This branch must exist — the generic
  // fall-through below would drop kind, grain, n and base, and the
  // structural hash would not match the one the engine recorded.
  if (def.operation === "ti") {
    const kind = def.kind ?? null;
    // A day offset is its own shape: a unit and a count, no grain.
    if (kind === "day_offset") {
      return {
        operation: "ti",
        kind,
        unit: def.unit ?? null,
        n: def.n ?? null,
        base: normalizeTiBase(def.base),
        filters: (def.filters ?? []).map(normalizeFilter)
      };
    }
    const out = {
      operation: "ti",
      kind,
      grain: def.grain ?? null,
      base: normalizeTiBase(def.base),
      filters: (def.filters ?? []).map(normalizeFilter)
    };
    if (kind === "shift") out.n = def.n ?? null;
    return out;
  }
  return {
    operation: def.operation,
    field: def.field ?? null,
    filters: (def.filters ?? []).map(normalizeFilter)
  };
}
function structuralHashOf(ir) {
  return addr({
    object_id: ir.object_id,
    definition: normalizeDefinition(ir.definition),
    scope: ir.scope ?? null,
    exclusions: ir.exclusions ?? [],
    unit: ir.unit ?? null,
    time_field: ir.time_field ?? null,
    // The calendar declaration is part of what the metric means, so it
    // is part of its structural hash. It is included only when there
    // is one, so every other IR hashes exactly as it always did.
    ...(ir.calendar !== undefined && ir.calendar !== null ? { calendar: ir.calendar } : {})
  });
}

// -- bitemporal selection, re-implemented from the intervals -----------
function selectVersion(rows, objectId, validAt, knownAt) {
  const valid = parseInstant(validAt);
  const known = parseInstant(knownAt);
  if (valid === null || known === null) return { status: "bad_time" };
  const candidates = rows.filter((row) => {
    if (row.object_id !== objectId) return false;
    const validFrom = parseInstant(row.valid_from);
    const validTo = row.valid_to ? parseInstant(row.valid_to) : Infinity;
    const knownFrom = parseInstant(row.known_from);
    const knownTo = row.known_to ? parseInstant(row.known_to) : Infinity;
    if (validFrom === null || knownFrom === null) return false;
    return valid >= validFrom && valid < validTo && known >= knownFrom && known < knownTo;
  });
  if (candidates.length === 0) return { status: "none" };
  if (candidates.length > 1) return { status: "overlap", candidates };
  return { status: "ok", row: candidates[0] };
}

// Every metric an IR references, one level deep: the arith operands,
// or a time-intelligence definition's base. A base is a reference like
// any other, resolved at the Ask's own times — like for like.
function operandClosure(ir, seen = new Set()) {
  const def = ir?.definition ?? {};
  const refs = [];
  if (def.operation === "arith") {
    for (const name of Object.keys(def.operands ?? {})) {
      refs.push(def.operands[name].object_id);
    }
  } else if (def.operation === "ti") {
    const base = def.base?.object_id;
    if (typeof base === "string" && base) refs.push(base);
  }
  for (const objectId of refs) {
    if (seen.has(objectId)) continue;
    seen.add(objectId);
  }
  return [...seen];
}

function definitionsFor(definitions, historyRows, objectId, validAt, knownAt) {
  const selection = selectVersion(historyRows, objectId, validAt, knownAt);
  if (selection.status !== "ok") {
    return { error: `KNOWLEDGE_SELECTION_${selection.status.toUpperCase()}` };
  }
  const matches = definitions.filter(
    (d) => d.object_id === objectId && d.structural_hash === selection.row.structural_hash
  );
  if (matches.length === 0) return { error: "DEFINITION_NOT_IN_PACKET" };
  if (matches.length > 1) return { error: "DEFINITION_AMBIGUOUS" };
  return { definition: matches[0], row: selection.row };
}

// The IRs an arith definition needs, resolved at the same (valid_at,
// known_at) as the metric itself.
function inputDefsFor(definitions, historyRows, ir, validAt, knownAt) {
  const out = {};
  const queue = [...operandClosure(ir)];
  const guard = new Set();
  while (queue.length) {
    const objectId = queue.shift();
    if (guard.has(objectId)) continue;
    guard.add(objectId);
    const resolved = definitionsFor(definitions, historyRows, objectId, validAt, knownAt);
    if (resolved.error) return { error: `${resolved.error}:${objectId}` };
    const inputIr = resolved.definition.ir;
    if (!inputIr) return { error: `DEFINITION_HAS_NO_IR:${objectId}` };
    out[objectId] = inputIr;
    for (const nested of operandClosure(inputIr)) queue.push(nested);
  }
  return { inputDefs: out };
}

function resolveDefinitionForMetric(definitions, metricName) {
  const wanted = String(metricName ?? "").toLowerCase();
  const exact = definitions.filter((d) => d.ir && d.ir.object_id === metricName);
  if (exact.length === 1) return { definition: exact[0] };
  const named = definitions.filter((d) => {
    if (!d.ir) return false;
    const names = [d.ir.label, ...(d.ir.synonyms ?? [])]
      .filter(Boolean)
      .map((n) => String(n).toLowerCase());
    return names.includes(wanted);
  });
  if (named.length === 1) return { definition: named[0] };
  if (exact.length > 1 || named.length > 1) return { error: "AMBIGUOUS_METRIC" };
  return { error: "METRIC_NOT_IN_PACKET" };
}

function subDec(a, b) {
  const [x, y, scale] = aligned(a, b);
  return { int: x - y, scale };
}
function decEqual(a, b) {
  const da = parseDec(a);
  const db = parseDec(b);
  if (!da || !db) return false;
  return cmpDec(da, db) === 0;
}

// -- a plain-English rendering of a meaning -----------------------------
function describeFilter(f) {
  const op = f?.operator ?? "eq";
  const value = f?.value === undefined ? null : f.value;
  if (op === "is_null") return `${f.field} is null`;
  if (op === "is_not_null") return `${f.field} is not null`;
  const rendered = Array.isArray(value) ? value.join(", ") : String(value);
  if (op === "eq") return `${f.field} = ${rendered}`;
  if (op === "neq") return `${f.field} != ${rendered}`;
  if (op === "in") return `${f.field} in (${rendered})`;
  if (op === "not_in") return `${f.field} not in (${rendered})`;
  if (op === "gt") return `${f.field} > ${rendered}`;
  if (op === "gte") return `${f.field} >= ${rendered}`;
  if (op === "lt") return `${f.field} < ${rendered}`;
  if (op === "lte") return `${f.field} <= ${rendered}`;
  return `${f.field} ${op} ${rendered}`;
}
function describeExpr(node) {
  if (!node || typeof node !== "object") return "?";
  if (typeof node.ref === "string") return node.ref;
  if (typeof node.lit === "string") return node.lit;
  if (node.op === "null_if_empty" || node.op === "zero_if_empty") {
    return `${node.op}(${node.guards.join(", ")}) then ${describeExpr(node.then)}`;
  }
  if (typeof node.op === "string" && Array.isArray(node.args)) {
    if (node.op === "neg") return `-${describeExpr(node.args[0])}`;
    const left = describeExpr(node.args[0]);
    const right = describeExpr(node.args[1]);
    if (node.op === "+") return `(${left} + ${right})`;
    if (node.op === "-") return `(${left} - ${right})`;
    if (node.op === "*") return `(${left} * ${right})`;
    if (node.op === "/") return `(${left} / ${right})`;
    return `${node.op}(${node.args.map(describeExpr).join(", ")})`;
  }
  return "?";
}
function describeIr(ir) {
  const def = ir?.definition ?? {};
  const filters = (def.filters ?? []).map(describeFilter);
  const withFilters = (text) => (filters.length ? `${text} where ${filters.join(" and ")}` : text);
  switch (def.operation) {
    case "sum":
      return withFilters(`sum(${def.field})`);
    case "count":
      return withFilters("count(*)");
    case "count_non_null":
      return withFilters(`count(${def.field})`);
    case "count_distinct":
      return withFilters(`count distinct(${def.field})`);
    case "average":
      return withFilters(`average(${def.field})`);
    case "min":
      return withFilters(`min(${def.field})`);
    case "max":
      return withFilters(`max(${def.field})`);
    case "ratio":
      return withFilters(
        `ratio(${describeSide(def.numerator)} / ${describeSide(def.denominator)})`
      );
    case "arith":
      return withFilters(describeExpr(def.expr));
    case "ti": {
      const base = def.base?.object_id ?? (def.base?.definition ? "its own measure" : "?");
      const what =
        def.kind === "to_date"
          ? `${def.grain} to date`
          : `${def.grain} back ${def.n ?? "?"}`;
      return withFilters(`${what} of ${base}`);
    }
    default:
      return def.operation ?? "(unknown operation)";
  }
}
function describeSide(side) {
  if (!side || typeof side !== "object") return "?";
  if (side.operation === "count") return "count(*)";
  if (side.operation === "count_non_null") return `count(${side.field})`;
  return `${side.operation}(${side.field})`;
}

// -- canonical order of a section ---------------------------------------
// The packet is machine-built, so a section that is not in canonical
// order was arranged by hand. That is worth reporting on its own.
function historySortKey(row) {
  return [
    row.object_id,
    row.known_from,
    row.valid_from,
    row.version,
    row.valid_to ?? "9999",
    row.known_to ?? "9999"
  ].join("\u0000");
}
function definitionSortKey(definition) {
  return `${definition.object_id}\u0000${definition.structural_hash}`;
}
function isSortedBy(items, keyOf) {
  for (let i = 1; i < items.length; i += 1) {
    const previous = keyOf(items[i - 1]);
    const current = keyOf(items[i]);
    if (!(previous < current)) return false;
  }
  return true;
}
function historyRowsFor(history, objectId, structuralHash) {
  return history.filter(
    (row) => row.object_id === objectId && row.structural_hash === structuralHash
  );
}

// -- packet checks ------------------------------------------------------
function verifyPacketEntry(entry) {
  const problems = [];
  if (!entry || entry.entry_version !== "jl.mantle-ledger.v1") {
    return ["UNSUPPORTED_ENTRY_VERSION"];
  }
  const receipt = entry.receipt ?? {};
  const self = verifyReceiptHash(receipt);
  if (self) problems.push(self);
  if (entry.receipt_hash !== receipt.receipt_hash) problems.push("ENTRY_RECEIPT_HASH_MISMATCH");
  let recomputed;
  try {
    recomputed = entryHashOf(entry);
  } catch {
    problems.push("ENTRY_NOT_CANONICAL");
  }
  if (recomputed && entry.entry_hash !== recomputed) problems.push("ENTRY_HASH_MISMATCH");
  try {
    if (addr(entry.input ?? null) !== receipt.input_hash) problems.push("INPUT_HASH_MISMATCH");
    if (addr(entry.output ?? null) !== receipt.output_hash) problems.push("OUTPUT_HASH_MISMATCH");
    const evidenceHashes = (entry.evidence ?? []).map((e) => addr(e)).sort();
    if (canon(evidenceHashes) !== canon(receipt.evidence_hashes ?? [])) {
      problems.push("EVIDENCE_HASH_MISMATCH");
    }
    (entry.evidence ?? []).forEach((e, i) => {
      const p = verifyReceiptHash(e);
      if (p) problems.push(`EVIDENCE_RECEIPT_INVALID:${i}:${p}`);
    });
  } catch {
    problems.push("ENTRY_NOT_CANONICAL");
  }
  return problems;
}

function verifyPacket(packet, { pubkeyPem = null, dataBytes = null } = {}) {
  const errors = [];
  const notes = [];
  const checks = [];

  // 1. the packet hash covers everything else.
  const { packet_hash: claimedHash, ...body } = packet;
  let recomputedHash = null;
  try {
    recomputedHash = addr(body);
  } catch {
    errors.push(fail("packet_hash", "PACKET_NOT_CANONICAL"));
  }
  if (recomputedHash !== null && claimedHash !== recomputedHash) {
    errors.push(fail("packet_hash", "PACKET_HASH_MISMATCH", { claimed: claimedHash, actual: recomputedHash }));
  }
  checks.push("packet_hash");

  if (packet.packet_version !== PACKET_VERSION) {
    errors.push(fail("packet_version", "UNSUPPORTED_PACKET_VERSION", packet.packet_version));
    return { valid: false, errors, checks, notes, packet };
  }

  const result = packet.result ?? {};
  const chain = packet.chain ?? {};
  const seal = packet.seal ?? {};
  const definitions = Array.isArray(packet.definitions) ? packet.definitions : [];
  const history = Array.isArray(packet.history) ? packet.history : [];
  const data = packet.data ?? {};

  // 2. the result entry stands on its own.
  const entryProblems = verifyPacketEntry(result);
  if (entryProblems.length) {
    errors.push(fail("result_entry", entryProblems[0], entryProblems));
  }
  checks.push("result_entry");

  // 3. the result is inside the chain the seal covers.
  const entryHashes = Array.isArray(chain.entry_hashes) ? chain.entry_hashes : null;
  if (!entryHashes) {
    errors.push(fail("inclusion", "CHAIN_MISSING"));
  } else {
    const seq = result.seq;
    if (!Number.isInteger(seq) || seq < 0 || seq >= entryHashes.length) {
      errors.push(fail("inclusion", "SEQ_OUT_OF_RANGE", seq));
    } else if (entryHashes[seq] !== result.entry_hash) {
      errors.push(fail("inclusion", "ENTRY_NOT_IN_CHAIN", { seq }));
    }
    const expectedPrev = seq === 0 ? null : entryHashes[seq - 1];
    if ((result.previous_entry_hash ?? null) !== expectedPrev) {
      errors.push(fail("inclusion", "PREVIOUS_ENTRY_HASH_MISMATCH"));
    }
    const target = seal.target ?? {};
    const chainHash = sha256hex(canon(entryHashes));
    if (chainHash !== target.chain_hash) {
      errors.push(fail("inclusion", "CHAIN_HASH_MISMATCH", { claimed: target.chain_hash, actual: chainHash }));
    }
    const head = entryHashes.length ? entryHashes[entryHashes.length - 1] : null;
    if (head !== target.ledger_head) {
      errors.push(fail("inclusion", "LEDGER_HEAD_MISMATCH", { claimed: target.ledger_head, actual: head }));
    }
    if (target.length !== entryHashes.length) {
      errors.push(fail("inclusion", "CHAIN_LENGTH_MISMATCH", { claimed: target.length, actual: entryHashes.length }));
    }
  }
  checks.push("inclusion");

  // 4. the seal is signed by the key that claims to have signed it.
  const embeddedPem = packet.public_key?.pem ?? null;
  let keyPem = embeddedPem;
  if (pubkeyPem) {
    const embeddedFingerprint = packet.public_key?.fingerprint ?? null;
    const givenFingerprint = `sha256:${sha256hex(pubkeyPem)}`;
    if (embeddedFingerprint && givenFingerprint !== embeddedFingerprint) {
      errors.push(fail("seal_signature", "PUBKEY_MISMATCH", { packet: embeddedFingerprint, given: givenFingerprint }));
    }
    keyPem = pubkeyPem;
  } else {
    notes.push(
      "key taken from the packet; get the company's public key independently to rule out a forged packet."
    );
  }
  if (keyPem) {
    const problem = sealSignatureProblem(seal, keyPem);
    if (problem) errors.push(fail("seal_signature", problem));
    else notes.push("seal signature verified against the public key in the packet.");
  } else {
    errors.push(fail("seal_signature", "NO_PUBLIC_KEY"));
  }
  checks.push("seal_signature");

  // 5. the definitions carry their own source, and the answer uses one.
  let sourceBytesMissing = 0;
  if (!isSortedBy(definitions, definitionSortKey)) {
    errors.push(fail("definitions", "DEFINITIONS_NOT_IN_CANONICAL_ORDER"));
  }
  if (!isSortedBy(history, historySortKey)) {
    errors.push(fail("definitions", "HISTORY_NOT_IN_CANONICAL_ORDER"));
  }
  for (const definition of definitions) {
    const source = definition.source ?? null;
    if (source) {
      if (source.bytes_b64 === null || source.bytes_b64 === undefined) {
        sourceBytesMissing += 1;
      } else {
        let bytes;
        try {
          bytes = Buffer.from(source.bytes_b64, "base64");
        } catch {
          errors.push(fail("definitions", "SOURCE_BYTES_NOT_BASE64", definition.object_id));
          continue;
        }
        if (source.file_sha256 && sha256hex(bytes) !== source.file_sha256) {
          errors.push(fail("definitions", "SOURCE_BYTES_HASH_MISMATCH", definition.object_id));
        }
      }
    }
    if (definition.ir) {
      let recomputed;
      try {
        recomputed = structuralHashOf(definition.ir);
      } catch {
        errors.push(fail("definitions", "IR_NOT_CANONICAL", definition.object_id));
        continue;
      }
      if (definition.structural_hash && recomputed !== definition.structural_hash) {
        errors.push(fail("definitions", "STRUCTURAL_HASH_MISMATCH", definition.object_id));
      }
    }
    // The definition must agree with the history rows it claims to come
    // from: same version, same place on both timelines, same source.
    const rows = historyRowsFor(history, definition.object_id, definition.structural_hash);
    if (rows.length === 0) {
      errors.push(fail("definitions", "DEFINITION_NOT_IN_HISTORY", definition.object_id));
      continue;
    }
    if (!rows.some((row) => row.version === definition.version)) {
      errors.push(fail("definitions", "VERSION_MISMATCH", definition.object_id));
    }
    if (
      !rows.some(
        (row) => row.valid_from === definition.valid_from && row.known_from === definition.known_from
      )
    ) {
      errors.push(fail("definitions", "TIMELINE_MISMATCH", definition.object_id));
    }
    const rowSource = rows.find((row) => row.source)?.source ?? null;
    if (rowSource && source) {
      if (
        rowSource.file_sha256 !== source.file_sha256 ||
        rowSource.commit !== source.commit ||
        rowSource.path !== source.path
      ) {
        errors.push(fail("definitions", "SOURCE_RECORD_MISMATCH", definition.object_id));
      }
    }
  }
  if (sourceBytesMissing) {
    notes.push(
      `${sourceBytesMissing} definition(s) carry no source bytes; their origin could not be checked.`
    );
  }
  const operation = result.receipt?.operation ?? null;
  if (operation === "ask") {
    const used = result.input?.meaning_ir ?? null;
    if (used) {
      const found = definitions.find(
        (d) =>
          d.object_id === used.object_id &&
          d.structural_hash === structuralHashOf(used) &&
          d.ir !== null
      );
      if (!found) errors.push(fail("definitions", "USED_DEFINITION_NOT_IN_PACKET", used.object_id));
    }
  } else if (operation === "explain-change") {
    for (const side of ["a", "b"]) {
      const used = result.input?.meaning_irs?.[side] ?? null;
      if (!used) continue;
      const found = definitions.find(
        (d) => d.object_id === used.object_id && d.structural_hash === structuralHashOf(used)
      );
      if (!found) errors.push(fail("definitions", "USED_DEFINITION_NOT_IN_PACKET", used.object_id));
    }
  }
  checks.push("definitions");

  // 6. knowledge time: the version the receipt used is the version the
  //    history rows select at (valid_at, known_at).
  const historyRows = history.filter((row) => row && typeof row === "object");
  let knowledgeOk = true;
  const knowledgeCheck = (objectId, validAt, knownAt, expectedVersion, expectedHash) => {
    const selection = selectVersion(historyRows, objectId, validAt, knownAt);
    if (selection.status !== "ok") {
      knowledgeOk = false;
      errors.push(fail("knowledge_time", `KNOWLEDGE_SELECTION_${selection.status.toUpperCase()}`, objectId));
      return null;
    }
    if (expectedVersion && selection.row.version !== expectedVersion) {
      knowledgeOk = false;
      errors.push(
        fail("knowledge_time", "VERSION_MISMATCH", {
          object_id: objectId,
          expected: expectedVersion,
          selected: selection.row.version
        })
      );
    }
    if (expectedHash && selection.row.structural_hash !== expectedHash) {
      knowledgeOk = false;
      errors.push(fail("knowledge_time", "STRUCTURAL_HASH_MISMATCH", objectId));
    }
    return selection.row;
  };
  if (operation === "ask") {
    const question = result.output?.question ?? {};
    const meaning = result.output?.meaning ?? null;
    if (meaning && question.valid_at && question.known_at) {
      knowledgeCheck(meaning.object_id, question.valid_at, question.known_at, meaning.version, meaning.structural_hash);
    }
  } else if (operation === "explain-change") {
    const request = result.output?.request ?? {};
    for (const side of ["a", "b"]) {
      const meaning = result.output?.definitions?.[side] ?? null;
      const period = side === "a" ? request.period_a : request.period_b;
      if (!meaning || !period) continue;
      const endLast = formatInstant(parseInstant(period.end) - 1);
      knowledgeCheck(meaning.object_id, period.start, request.known_at, meaning.version, meaning.structural_hash);
      knowledgeCheck(meaning.object_id, endLast, request.known_at, meaning.version, meaning.structural_hash);
    }
  } else if (operation === "verify-claim") {
    const question = result.output?.question ?? {};
    const resolved = resolveDefinitionForMetric(definitions, question.metric);
    if (resolved.error) {
      knowledgeOk = false;
      errors.push(fail("knowledge_time", resolved.error, question.metric));
    } else if (question.valid_at && question.known_at) {
      const selection = selectVersion(historyRows, resolved.definition.object_id, question.valid_at, question.known_at);
      if (selection.status !== "ok") {
        knowledgeOk = false;
        errors.push(fail("knowledge_time", `KNOWLEDGE_SELECTION_${selection.status.toUpperCase()}`));
      } else if (selection.row.structural_hash !== resolved.definition.structural_hash) {
        knowledgeOk = false;
        errors.push(fail("knowledge_time", "STRUCTURAL_HASH_MISMATCH", resolved.definition.object_id));
      }
    }
  }
  checks.push("knowledge_time");

  // 7. replay: the same data, the same answer, computed here.
  let replayed = false;
  let replayStatus = "skipped";
  const recordedData = result.output?.data ?? (result.output?.question?.data ?? null);
  if (recordedData?.name && data.name && recordedData.name !== data.name) {
    errors.push(fail("replay", "DATA_NAME_MISMATCH", { recorded: recordedData.name, packet: data.name }));
  }
  if (recordedData?.sha256 && data.sha256 && recordedData.sha256 !== data.sha256) {
    errors.push(fail("replay", "DATA_HASH_MISMATCH", { recorded: recordedData.sha256, packet: data.sha256 }));
  }
  if (dataBytes) {
    if (data.sha256 && sha256hex(dataBytes) !== data.sha256) {
      errors.push(fail("replay", "DATA_HASH_MISMATCH"));
    } else {
      let rows;
      try {
        rows = loadRows(dataBytes, data.name ?? "data.csv");
      } catch (error) {
        errors.push(fail("replay", `DATA_UNREADABLE:${error.message}`));
        rows = null;
      }
      if (rows) {
        const replay = replayPacketResult({ result, definitions, historyRows, rows, operation });
        if (replay.error) {
          errors.push(fail("replay", replay.error));
        } else {
          replayed = true;
          replayStatus = "match";
        }
      }
    }
  } else {
    replayStatus = "no-data";
    notes.push("no data bytes available, so the answer was not recomputed.");
  }
  checks.push("replay");

  return { valid: errors.length === 0, errors, checks, notes, packet, replayed, replayStatus, knowledgeOk };
}

// Recompute what the receipt claims, with this file's own compute.
function replayPacketResult({ result, definitions, historyRows, rows, operation }) {
  const output = result.output ?? {};
  if (operation === "ask") {
    if (output.verdict === "REFUSED") {
      if (output.answer !== null) return { error: "REFUSED_WITH_ANSWER" };
      return { ok: true };
    }
    const question = output.question ?? {};
    const meaning = output.meaning ?? null;
    if (!meaning) return { error: "REPLAY_INPUT_MISSING" };
    const resolved = definitionsFor(definitions, historyRows, meaning.object_id, question.valid_at, question.known_at);
    if (resolved.error) return { error: resolved.error };
    const ir = resolved.definition.ir;
    if (!ir) return { error: "DEFINITION_HAS_NO_IR" };
    const inputs = inputDefsFor(definitions, historyRows, ir, question.valid_at, question.known_at);
    if (inputs.error) return { error: inputs.error };
    let computed;
    let tiWindows;
    try {
      computed = replayAnswer(ir, question, rows, inputs.inputDefs);
      tiWindows = tiWindowsFor(ir.definition, inputs.inputDefs, question.window ?? null, question.period ?? null);
    } catch (error) {
      return { error: `REPLAY_COMPUTE_FAILED:${error.message}` };
    }
    if (canon(computed.groups) !== canon(output.answer?.groups ?? null)) {
      return { error: "REPLAY_ANSWER_MISMATCH" };
    }
    const dataInfo = output.data ?? {};
    if (
      computed.rows_scanned !== (dataInfo.rows_scanned ?? null) ||
      computed.rows_matched !== (dataInfo.rows_matched ?? null)
    ) {
      return { error: "REPLAY_ROW_COUNT_MISMATCH" };
    }
    // The windows a time-intelligence answer actually read over are
    // part of the claim, so they are recomputed here as well.
    if (canon(tiWindows) !== canon(output.ti_windows ?? [])) {
      return { error: "REPLAY_TI_WINDOW_MISMATCH" };
    }
    return { ok: true };
  }

  if (operation === "explain-change") {
    if (output.verdict === "REFUSED") {
      if (output.values !== null) return { error: "REFUSED_WITH_VALUES" };
      return { ok: true };
    }
    const request = output.request ?? {};
    const meaningA = output.definitions?.a ?? null;
    const meaningB = output.definitions?.b ?? null;
    if (!meaningA || !meaningB) return { error: "REPLAY_INPUT_MISSING" };
    const resolveSide = (meaning, period) => {
      const resolved = definitionsFor(definitions, historyRows, meaning.object_id, period.start, request.known_at);
      if (resolved.error) return { error: resolved.error };
      const ir = resolved.definition.ir;
      if (!ir) return { error: "DEFINITION_HAS_NO_IR" };
      const inputs = inputDefsFor(definitions, historyRows, ir, period.start, request.known_at);
      if (inputs.error) return { error: inputs.error };
      return { ir, inputDefs: inputs.inputDefs };
    };
    const sideA = resolveSide(meaningA, request.period_a);
    if (sideA.error) return { error: sideA.error };
    const sideB = resolveSide(meaningB, request.period_b);
    if (sideB.error) return { error: sideB.error };
    const questionFor = (period) => ({
      metric: request.metric,
      window: period,
      group_by: [],
      filters: request.filters ?? [],
      valid_at: period.start,
      known_at: request.known_at,
      data: request.data ?? null
    });
    let aUnderDa;
    let bUnderDa;
    let bUnderDb;
    let tiWindows = [];
    try {
      aUnderDa = replayAnswer(sideA.ir, questionFor(request.period_a), rows, sideA.inputDefs);
      bUnderDa = replayAnswer(sideA.ir, questionFor(request.period_b), rows, sideA.inputDefs);
      bUnderDb = replayAnswer(sideB.ir, questionFor(request.period_b), rows, sideB.inputDefs);
      // The windows a change actually read over: the union of the three
      // computations, in order, without repeats.
      for (const [sideIr, sideInputs, period] of [
        [sideA.ir, sideA.inputDefs, request.period_a],
        [sideA.ir, sideA.inputDefs, request.period_b],
        [sideB.ir, sideB.inputDefs, request.period_b]
      ]) {
        for (const entry of tiWindowsFor(sideIr.definition, sideInputs, period, null)) {
          if (!tiWindows.some((w) => canon(w) === canon(entry))) tiWindows.push(entry);
        }
      }
    } catch (error) {
      return { error: `REPLAY_COMPUTE_FAILED:${error.message}` };
    }
    const recorded = output.values ?? {};
    const pairs = [
      [aUnderDa, recorded.a_under_da],
      [bUnderDa, recorded.b_under_da],
      [bUnderDb, recorded.b_under_db]
    ];
    for (const [computed, claim] of pairs) {
      if (!claim) return { error: "REPLAY_INPUT_MISSING" };
      const value = computed.groups?.[0]?.value ?? null;
      if (!decEqual(value ?? "", claim.value ?? "")) return { error: "REPLAY_ANSWER_MISMATCH" };
    }
    const dec = (v) => parseDec(v);
    const a = dec(aUnderDa.groups?.[0]?.value);
    const bUnderDaDec = dec(bUnderDa.groups?.[0]?.value);
    const bUnderDbDec = dec(bUnderDb.groups?.[0]?.value);
    if (!a || !bUnderDaDec || !bUnderDbDec) return { error: "REPLAY_COMPUTE_FAILED:BAD_VALUE" };
    const business = subDec(bUnderDaDec, a);
    const definition = subDec(bUnderDbDec, bUnderDaDec);
    const reported = subDec(bUnderDbDec, a);
    if (!decEqual(fmtDec(business), output.business_effect?.value ?? "")) {
      return { error: "REPLAY_BUSINESS_EFFECT_MISMATCH" };
    }
    if (!decEqual(fmtDec(definition), output.definition_effect?.value ?? "")) {
      return { error: "REPLAY_DEFINITION_EFFECT_MISMATCH" };
    }
    if (!decEqual(fmtDec(reported), output.reported_change?.value ?? "")) {
      return { error: "REPLAY_REPORTED_CHANGE_MISMATCH" };
    }
    if (canon(tiWindows) !== canon(output.ti_windows ?? [])) {
      return { error: "REPLAY_TI_WINDOW_MISMATCH" };
    }
    return { ok: true };
  }

  if (operation === "verify-claim") {
    const question = output.question ?? {};
    const resolved = resolveDefinitionForMetric(definitions, question.metric);
    if (resolved.error) return { error: resolved.error };
    const ir = resolved.definition.ir;
    if (!ir) return { error: "DEFINITION_HAS_NO_IR" };
    const inputs = inputDefsFor(definitions, historyRows, ir, question.valid_at, question.known_at);
    if (inputs.error) return { error: inputs.error };
    let computed;
    try {
      computed = replayAnswer(ir, question, rows, inputs.inputDefs);
    } catch (error) {
      return { error: `REPLAY_COMPUTE_FAILED:${error.message}` };
    }
    if (canon(computed.groups) !== canon(output.computed?.groups ?? null)) {
      return { error: "REPLAY_ANSWER_MISMATCH" };
    }
    // The claim verdict is recomputed from the same numbers.
    const claimedGroups = output.claimed?.groups ?? [];
    const computedGroups = computed.groups ?? [];
    const computedByKey = new Map(computedGroups.map((g) => [canon(g.key), g]));
    const claimedByKey = new Map(claimedGroups.map((g) => [canon(g.key), g]));
    const missing = [...computedByKey.keys()].filter((k) => !claimedByKey.has(k));
    const extra = [...claimedByKey.keys()].filter((k) => !computedByKey.has(k));
    const tolerance = parseDec(output.tolerance ?? "0");
    const toleranceNonZero = tolerance ? tolerance.int !== 0n : false;
    let allEqual = missing.length === 0 && extra.length === 0;
    let allWithin = allEqual;
    for (const [key, claimedGroup] of claimedByKey) {
      const got = computedByKey.get(key);
      if (!got) continue;
      if (got.value === null) {
        allEqual = false;
        allWithin = false;
        continue;
      }
      const claimedDec = parseDec(claimedGroup.value);
      const computedDec = parseDec(got.value);
      if (!claimedDec || !computedDec) {
        allEqual = false;
        allWithin = false;
        continue;
      }
      const delta = subDec(claimedDec, computedDec);
      if (cmpDec(delta, { int: 0n, scale: 0 }) !== 0) allEqual = false;
      const abs = delta.int < 0n ? { int: -delta.int, scale: delta.scale } : delta;
      if (tolerance && cmpDec(abs, tolerance) > 0) allWithin = false;
    }
    const verdict =
      allEqual && !toleranceNonZero
        ? "MATCH"
        : allEqual || allWithin
          ? "MATCH_WITHIN_TOLERANCE"
          : "MISMATCH";
    if (verdict !== output.claim_verdict) {
      return { error: "REPLAY_CLAIM_VERDICT_MISMATCH", expected: output.claim_verdict, actual: verdict };
    }
    return { ok: true };
  }

  return { error: `UNSUPPORTED_OPERATION:${operation}` };
}

// -- the plain-English report -------------------------------------------
function packetTextReport(verification) {
  const packet = verification.packet ?? {};
  const result = packet.result ?? {};
  const output = result.output ?? {};
  const definitions = Array.isArray(packet.definitions) ? packet.definitions : [];
  const history = Array.isArray(packet.history) ? packet.history : [];
  const chain = packet.chain ?? {};
  const lines = [];

  const metric =
    output.question?.metric ?? output.request?.metric ?? result.receipt?.operation ?? "(request)";
  const answer = output.answer?.groups?.[0]?.value ?? null;
  const verdict = output.verdict ?? output.claim_verdict ?? null;

  if (verdict === "REFUSED") {
    lines.push(`Refused. The question was not answered.`);
    lines.push(`Reason: ${(output.reasons ?? []).join(", ") || "none recorded"}.`);
  } else if (output.business_effect) {
    lines.push(
      `Change from ${output.request?.period_a?.start} to ${output.request?.period_b?.start}: ` +
        `business effect ${output.business_effect.value}, definition effect ${output.definition_effect.value}, ` +
        `reported change ${output.reported_change.value}.`
    );
  } else if (output.claim_verdict) {
    lines.push(
      `Claim of someone else's number: ${output.claim_verdict}. ` +
        `Computed ${output.computed?.groups?.[0]?.value ?? "null"}, ` +
        `claimed ${output.claimed?.groups?.[0]?.value ?? "null"}.`
    );
  } else if (answer !== null) {
    lines.push(`${metric} = ${answer}.`);
  } else {
    lines.push(`${metric}: no answer recorded.`);
  }

  const meaning = output.meaning ?? output.definitions?.a ?? null;
  if (meaning) {
    const definition = definitions.find((d) => d.object_id === meaning.object_id && d.version === meaning.version);
    const rows = history.filter((row) => row.object_id === meaning.object_id);
    const row = rows.find((r) => r.version === meaning.version);
    const description = definition?.ir ? describeIr(definition.ir) : "(definition not in packet)";
    lines.push(
      `Definition ${meaning.version} ("${description}"), effective ${meaning.effective_from ?? row?.valid_from ?? "?"}` +
        `${row?.commit ? `, recorded in git commit ${row.commit}` : ""}` +
        `${row?.known_from ? ` on ${row.known_from}` : ""}.`
    );
  }
  if (output.question?.known_at) {
    lines.push(`Answered as known on ${output.question.known_at}.`);
  } else if (output.request?.known_at) {
    lines.push(`Answered as known on ${output.request.known_at}.`);
  }
  // A time-intelligence answer says which window it actually read.
  for (const w of output.ti_windows ?? []) {
    const what = w.kind === "to_date" ? `${w.grain} to date` : `${w.grain} back ${w.n}`;
    lines.push(
      `Read ${w.base} over ${w.window.start} to ${w.window.end} (${what}, like for like).`
    );
  }

  lines.push(
    verification.replayed
      ? "Recomputed independently: match."
      : "Recomputed independently: not attempted (no data bytes available)."
  );

  const length = Array.isArray(chain.entry_hashes) ? chain.entry_hashes.length : 0;
  const seq = Number.isInteger(result.seq) ? result.seq : 0;
  lines.push(
    `Sealed in ledger entry ${seq + 1} of ${length}; ` +
      `signature ${verification.errors.length ? "NOT valid" : "valid"} for key ${packet.public_key?.fingerprint ?? "?"}.`
  );
  for (const note of verification.notes) lines.push(note);
  for (const error of verification.errors) {
    lines.push(`FAILED ${error.check}: ${error.reason}`);
  }
  lines.push(verification.valid ? "VERDICT: valid." : "VERDICT: invalid.");
  return lines.join("\n");
}


// ---------------- main ----------------
const USAGE =
  "usage: node verifier/mantle-verify.mjs <ledger.jsonl> [--pubkey key.pem] [--replay <repo> <data-dir>]\n" +
  "       node verifier/mantle-verify.mjs --packet <packet.json> [--pubkey key.pem] [--data <file>] [--text]";

function readPacket(packetPath) {
  let text;
  try {
    text = readFileSync(packetPath, "utf8");
  } catch {
    return { error: "PACKET_UNREADABLE" };
  }
  let packet;
  try {
    packet = JSON.parse(text);
  } catch {
    return { error: "PACKET_NOT_JSON" };
  }
  if (!packet || typeof packet !== "object" || Array.isArray(packet)) {
    return { error: "PACKET_NOT_AN_OBJECT" };
  }
  return { packet };
}

function runPacketMode(packetPath, { pubkeyPath = null, dataPath = null, text = false } = {}) {
  const loaded = readPacket(packetPath);
  if (loaded.error) {
    process.stderr.write(`INVALID ${loaded.error}: ${packetPath}\n`);
    process.exitCode = 1;
    return;
  }
  let pubkeyPem = null;
  if (pubkeyPath) {
    try {
      pubkeyPem = readFileSync(pubkeyPath, "utf8");
    } catch {
      process.stderr.write("INVALID PUBKEY_UNREADABLE\n");
      process.exitCode = 1;
      return;
    }
  }
  let dataBytes = null;
  if (dataPath) {
    try {
      dataBytes = readFileSync(dataPath);
    } catch {
      process.stderr.write("INVALID DATA_UNREADABLE\n");
      process.exitCode = 1;
      return;
    }
  } else {
    const embedded = loaded.packet?.data?.bytes_b64;
    if (typeof embedded === "string" && embedded.length) {
      try {
        dataBytes = Buffer.from(embedded, "base64");
      } catch {
        dataBytes = null;
      }
    }
  }
  const verification = verifyPacket(loaded.packet, { pubkeyPem, dataBytes });
  if (text) {
    process.stdout.write(`${packetTextReport(verification)}\n`);
  } else {
    process.stdout.write(
      `${JSON.stringify(
        {
          valid: verification.valid,
          packet_version: loaded.packet.packet_version ?? null,
          packet_hash: loaded.packet.packet_hash ?? null,
          checks: verification.checks,
          replayed: verification.replayed,
          replay: verification.replayStatus,
          errors: verification.errors,
          notes: verification.notes
        },
        null,
        2
      )}\n`
    );
  }
  if (!verification.valid) {
    const first = verification.errors[0];
    process.stderr.write(`INVALID ${first.check}: ${first.reason}\n`);
    process.exitCode = 2;
  }
}

function main() {
  const args = process.argv.slice(2);
  let ledgerPath = null;
  let packetPath = null;
  let pubkeyPath = null;
  let dataPath = null;
  let replay = null;
  let text = false;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--packet") {
      packetPath = args[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === "--pubkey") {
      pubkeyPath = args[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === "--data") {
      dataPath = args[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === "--text") {
      text = true;
      continue;
    }
    if (arg === "--replay") {
      replay = { repo: args[i + 1] ?? "", dataDir: args[i + 2] ?? "" };
      i += 2;
      continue;
    }
    if (!arg.startsWith("--") && ledgerPath === null) ledgerPath = arg;
  }
  if (packetPath) {
    runPacketMode(packetPath, { pubkeyPath, dataPath, text });
    return;
  }
  if (!ledgerPath) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 1;
    return;
  }
  const result = verifyLedger(ledgerPath, { pubkeyPath, replay });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.valid) {
    const first = result.errors[0];
    process.stderr.write(`INVALID line ${first.index}: ${first.reason}\n`);
    process.exitCode = 2;
  }
}
main();




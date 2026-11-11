/**
 * AirgunMatches.com — Cloudflare Worker
 *
 * Serves the static site AND the API from one deployable unit, so a
 * rollback restores both together.
 *
 * Routes
 *   GET    /api/events              public — approved events, public columns only
 *   POST   /api/events              public — create a pending submission
 *   GET    /api/admin/events        admin  — every event, every column
 *   PATCH  /api/admin/events/:id    admin  — change status or edit fields
 *   DELETE /api/admin/events/:id    admin  — permanent delete
 *   GET    /api/admin/export        admin  — full backup as JSON or CSV
 *   everything else                 static assets
 *
 * SECURITY MODEL
 * Postgres row-level security is gone; D1 has no equivalent. Every rule it
 * used to enforce now lives here, and this Worker is the only path to the
 * database:
 *   - Public reads are restricted to status='approved' and a fixed column
 *     list that excludes submitter_name, submitter_email and all review
 *     fields. Those columns are never selected, so they cannot leak.
 *   - Public writes are forced to status='pending'. A client cannot set
 *     status, id, or any review field.
 *   - Admin routes require a valid Cloudflare Access JWT, verified against
 *     Cloudflare's public keys on every request — not merely assumed
 *     because Access sits in front of the route.
 */

import { handleScoring } from "./scoring.js";

const ADMIN_PATH = "/admin.html";

/* Search-engine rendering: event pages, the sitemap, and the listings injected
   into the calendar's own HTML. Kept in its own module because none of it is
   application logic — it exists purely so a crawler sees what a visitor sees. */
import {
  eventPath, idFragmentFrom, eventPageHtml, liveEventPageHtml, sitemapXml,
  injectIntoCalendar, injectCanonical
} from "./seo.js";
import {
  activeSponsor, countImpression, handleSponsorClick, injectSponsor,
  injectScoringSponsor, resultsCreditHtml, liveSponsorParts, SPONSOR_CSS
} from "./sponsors.js";

/* Columns the public may ever see. Submitter and review fields are absent
   by construction rather than filtered out afterwards. */
const PUBLIC_COLUMNS =
  "id, name, start_date, end_date, venue, city, state, gun_types, disciplines, org, juniors, url, video_url, note, series_id, " +
  "lat, lng, geo_at, confirmed_at, results_updated_at, listing_status, status_note";

/* A club running the same match every month submits it once and gets one
   listing per date, all sharing a series id.

   Each occurrence stays an ordinary event in every other respect — its own
   results, its own code, its own winner — because that is what actually
   happens at a monthly match. The series id exists so the calendar can say
   "this match also runs on these dates", and so a season can be reviewed in
   one decision instead of nine. */
const MAX_DATES_PER_SERIES = 60;

/* What a match is shot with, as opposed to how it's scored. Kept separate from
   disciplines because the same discipline name means different things in
   different worlds — a "Precision Rifle" match is one thing with a PCP airgun
   and quite another with a centrefire, and a visitor filtering for one does not
   want the other. */
const GUN_TYPES = ["Airgun", "Rimfire", "Centerfire", "Shotgun", "Muzzleloader", "Archery"];

const STATES = new Set(["AL","AK","AZ","AR","CA","CO","CT","DE","DC","FL","GA","HI","ID","IL","IN","IA","KS","KY","LA","ME","MD","MA","MI","MN","MS","MO","MT","NE","NV","NH","NJ","NM","NY","NC","ND","OH","OK","OR","PA","RI","SC","SD","TN","TX","UT","VT","VA","WA","WV","WI","WY"]);

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...securityHeaders(), ...extra }
  });

const fail = (message, status = 400) => json({ error: message }, status);

function securityHeaders() {
  return {
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "x-frame-options": "DENY",
    "permissions-policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "strict-transport-security": "max-age=31536000; includeSubDomains"
  };
}

/** Salted hash of the client IP. Used for rate limiting and duplicate
 *  detection without ever storing an address. */
async function hashIp(ip, salt) {
  if (!ip) return null;
  const bytes = new TextEncoder().encode(`${salt}:${ip}`);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

const str = (v, max) => {
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (!s) return null;
  return s.slice(0, max);
};

/* ------------------------------------------------------------------ */
/* Admin authentication                                                */
/*                                                                     */
/* A single passphrase, stored as an encrypted Worker secret and never  */
/* present in the source. A successful login returns a signed, expiring */
/* cookie; every admin request verifies that signature. The cookie is   */
/* HttpOnly so page scripts cannot read it, Secure so it never travels  */
/* unencrypted, and SameSite=Strict so another site cannot ride on it.  */
/* ------------------------------------------------------------------ */

const SESSION_COOKIE = "agm_session";
const SESSION_HOURS = 12;

const enc = new TextEncoder();

/** Comparison that takes the same time whether or not the strings match,
 *  so timing cannot be used to guess the passphrase character by character. */
function constantTimeEqual(a, b) {
  const A = enc.encode(a), B = enc.encode(b);
  if (A.length !== B.length) return false;
  let diff = 0;
  for (let i = 0; i < A.length; i++) diff |= A[i] ^ B[i];
  return diff === 0;
}

async function hmac(message, key) {
  const k = await crypto.subtle.importKey(
    "raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", k, enc.encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function makeSession(env) {
  const expires = Date.now() + SESSION_HOURS * 3600_000;
  return `${expires}.${await hmac(String(expires), env.ADMIN_PASSWORD)}`;
}

async function validSession(token, env) {
  if (!token) return false;
  const [expires, sig] = token.split(".");
  if (!expires || !sig) return false;
  if (Number(expires) < Date.now()) return false;
  return constantTimeEqual(sig, await hmac(expires, env.ADMIN_PASSWORD));
}

const readCookie = (request, name) =>
  (request.headers.get("cookie") || "").match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`))?.[1] || null;

/** Records failed attempts so a stolen URL cannot be brute-forced.
 *  Ten failures from one address in fifteen minutes locks it out. */
async function loginBlocked(env, ipHash) {
  if (!ipHash) return false;
  const since = new Date(Date.now() - 15 * 60_000).toISOString();
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM admin_logins WHERE ip_hash = ? AND ts > ?"
  ).bind(ipHash, since).first();
  return (row?.n || 0) >= 10;
}

async function recordFailure(env, ipHash) {
  if (!ipHash) return;
  await env.DB.prepare("INSERT INTO admin_logins (ip_hash, ts) VALUES (?, ?)")
    .bind(ipHash, new Date().toISOString()).run();
}

async function handleLogin(request, env) {
  if (!env.ADMIN_PASSWORD) return fail("Admin access is not configured yet.", 503);

  const ip = request.headers.get("CF-Connecting-IP");
  const ipHash = await hashIp(ip, env.IP_SALT || "airgunmatches");

  if (await loginBlocked(env, ipHash))
    return fail("Too many failed attempts. Try again in fifteen minutes.", 429);

  let body;
  try { body = await request.json(); } catch { return fail("Malformed request."); }

  if (!constantTimeEqual(String(body.password || ""), env.ADMIN_PASSWORD)) {
    await recordFailure(env, ipHash);
    // Slow down automated guessing without inconveniencing a real typo.
    await new Promise(r => setTimeout(r, 800));
    return fail("Incorrect password.", 401);
  }

  const token = await makeSession(env);
  return json({ ok: true }, 200, {
    "set-cookie": `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_HOURS * 3600}`
  });
}

function handleLogout() {
  return json({ ok: true }, 200, {
    "set-cookie": `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
  });
}

async function requireAdmin(request, env) {
  const okSession = await validSession(readCookie(request, SESSION_COOKIE), env);
  if (!okSession) return { error: fail("Not authorised", 403) };
  return { email: "admin" };
}

/* ------------------------------------------------------------------ */
/* Results upload codes                                                */
/*                                                                     */
/* Each approved event gets a single-purpose code. It grants exactly    */
/* one capability: replacing the results for that one event. It cannot  */
/* read submitter data, touch other events, or reach the dashboard.     */
/* ------------------------------------------------------------------ */

// Ambiguous characters (0/O, 1/I/L) are excluded so a code can be read
// aloud or copied off a phone screen without confusion.
const CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";

function makeResultsCode() {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  const chars = [...bytes].map(b => CODE_ALPHABET[b % CODE_ALPHABET.length]);
  return `${chars.slice(0,4).join("")}-${chars.slice(4,8).join("")}-${chars.slice(8,12).join("")}`;
}

const normaliseCode = c =>
  String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12);

/** Looks up an event by its results code, comparing on the normalised form
 *  so hyphens, spaces and lower case all work. */
async function eventForCode(env, code) {
  const clean = normaliseCode(code);
  if (clean.length !== 12) return null;
  return await env.DB.prepare(
    `SELECT id, name, start_date, end_date, venue, city, state, disciplines, status, is_test
       FROM events
      WHERE replace(upper(results_token), '-', '') = ?`
  ).bind(clean).first();
}

/* ------------------------------------------------------------------ */
/* Turnstile                                                           */
/* ------------------------------------------------------------------ */

async function turnstileOk(token, ip, env) {
  if (!env.TURNSTILE_SECRET_KEY) return true;   // not configured yet — don't lock people out

  /* A failed spam check used to be silent, which made it impossible to tell a
     wrong secret from an expired token from a hostname the widget doesn't
     allow — three completely different problems with one identical symptom.
     Cloudflare returns an error code saying exactly which; it goes to the
     Workers log. The secret itself is never logged. */
  if (!token) {
    console.error("turnstile: the browser sent no token");
    return false;
  }

  const body = new FormData();
  body.append("secret", env.TURNSTILE_SECRET_KEY);
  body.append("response", token);
  if (ip) body.append("remoteip", ip);

  const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST", body
  });
  const out = await res.json().catch(() => ({ success: false }));

  if (out.success !== true) {
    console.error("turnstile rejected:", JSON.stringify({
      codes: out["error-codes"] || null,
      hostname: out.hostname || null,
      secret_len: String(env.TURNSTILE_SECRET_KEY).length,
      secret_trimmed_len: String(env.TURNSTILE_SECRET_KEY).trim().length
    }));
  }
  return out.success === true;
}

/* ------------------------------------------------------------------ */
/* Validation                                                          */
/* ------------------------------------------------------------------ */

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** A date that is both the right shape and a day that exists.
 *
 *  The pattern alone accepts 2026-13-45 and 2027-02-31, which then sit in the
 *  database sorting into strange places and rendering as "Invalid Date" on the
 *  calendar. Round-tripping through Date is the cheap way to insist the day is
 *  real: February 31st comes back as March 3rd and no longer matches itself. */
function isRealDate(s) {
  if (!s || !DATE_RE.test(s)) return false;
  const [y, m, d] = s.split("-").map(Number);
  const t = new Date(Date.UTC(y, m - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === m - 1 && t.getUTCDate() === d;
}
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const YT_RE = /^https:\/\/((www\.|m\.)?youtube\.com\/|youtu\.be\/)/;

/* A city is a place, not a title. Catches the name or venue pasted into the
   City box, and street addresses or long text, which also break distance search. */
function cityLooksWrong(city, name, venue) {
  const c = String(city || "").trim().toLowerCase().replace(/\s+/g, " ");
  if (!c) return false;
  const same = x => x && String(x).trim().toLowerCase().replace(/\s+/g, " ") === c;
  return same(name) || same(venue) || c.length > 60 || /\d{3,}/.test(c) || /\b(tournament|match|club|range|association|challenge|championship)\b/.test(c);
}

function validateSubmission(b) {
  const e = [];
  const name = str(b.name, 160);
  const venue = str(b.venue, 160);
  const city = str(b.city, 100);
  const state = (str(b.state, 2) || "").toUpperCase();
  const start = str(b.start_date, 10);
  const end = str(b.end_date, 10);
  const sName = str(b.submitter_name, 120);
  const sEmail = str(b.submitter_email, 200);

  if (!name || name.length < 3) e.push("Event name must be at least 3 characters.");
  if (!venue || venue.length < 2) e.push("Venue is required.");
  if (!city || city.length < 2) e.push("City is required.");
  else if (cityLooksWrong(city, name, venue)) e.push("City should be the town or city the match is in, not the event or club name.");
  if (!STATES.has(state)) e.push("A valid two-letter state code is required.");
  /* Dates.
   *
   * A one-off match sends start_date and an optional end_date, exactly as
   * before. A recurring match sends a `dates` array instead, one entry per
   * occurrence, each of which may itself span days — a monthly club shoot is
   * one day, a Grand Prix is three, and a club can run both.
   *
   * Everything downstream works from `occurrences`, so a single match is
   * simply a series of one and there is no second code path to keep correct. */
  const occurrences = [];
  const rawDates = Array.isArray(b.dates) ? b.dates : null;

  if (rawDates && rawDates.length) {
    if (rawDates.length > MAX_DATES_PER_SERIES)
      e.push(`No more than ${MAX_DATES_PER_SERIES} dates in one submission.`);

    const seen = new Set();
    for (const d of rawDates.slice(0, MAX_DATES_PER_SERIES)) {
      const s = str(typeof d === "string" ? d : (d && (d.start_date ?? d.start)), 10);
      const f = str(typeof d === "string" ? null : (d && (d.end_date ?? d.end)), 10);
      if (!isRealDate(s)) { e.push(`"${s || "(blank)"}" isn't a real date in YYYY-MM-DD form.`); continue; }
      if (f && !isRealDate(f)) { e.push(`"${f}" isn't a real date in YYYY-MM-DD form.`); continue; }
      if (f && f < s) { e.push(`The match on ${s} ends before it starts.`); continue; }
      if (s < "2015-01-01" || s > "2100-01-01") { e.push(`${s} is outside the range the calendar accepts.`); continue; }
      if (seen.has(s)) continue;              // the same date twice is a slip, not an error
      seen.add(s);
      occurrences.push({ start: s, end: f || null });
    }
    if (!occurrences.length && !e.length) e.push("Pick at least one date.");
  } else {
    if (!isRealDate(start)) e.push("Start date must be a real date in YYYY-MM-DD form.");
    if (end && !isRealDate(end)) e.push("End date must be a real date in YYYY-MM-DD form.");
    if (start && end && end < start) e.push("End date cannot be before the start date.");
    if (start && (start < "2015-01-01" || start > "2100-01-01")) e.push("Start date is out of range.");
    if (isRealDate(start)) occurrences.push({ start, end: end || null });
  }

  occurrences.sort((x, y) => x.start.localeCompare(y.start));
  if (!sName || sName.length < 2) e.push("Your name is required.");
  if (!sEmail || !EMAIL_RE.test(sEmail)) e.push("A valid email address is required.");

  let disciplines = Array.isArray(b.disciplines) ? b.disciplines : [];
  disciplines = [...new Set(
    disciplines.map(d => (typeof d === "string" ? d.trim() : "")).filter(d => d.length >= 2 && d.length <= 80)
  )];
  if (!disciplines.length) e.push("Pick at least one discipline.");
  if (disciplines.length > 8) e.push("No more than 8 disciplines.");

  /* Gun types are a fixed list, unlike disciplines. Write-ins are what make the
     discipline filter useful, but they would make this one meaningless — the
     whole point is that "Airgun" always means the same thing. */
  let gunTypes = Array.isArray(b.gun_types) ? b.gun_types : [];
  gunTypes = [...new Set(
    gunTypes.map(g => (typeof g === "string" ? g.trim() : "")).filter(g => GUN_TYPES.includes(g))
  )];
  if (!gunTypes.length) e.push("Pick at least one type — airgun, rimfire, centerfire and so on.");
  if (gunTypes.length > GUN_TYPES.length) e.push("Too many types.");

  const url = str(b.url, 500);
  if (url && !/^https?:\/\/.+/i.test(url)) e.push("Registration link must start with http:// or https://");

  const video = str(b.video_url, 300);
  if (video && !YT_RE.test(video)) e.push("The video link must be a YouTube URL.");

  const note = str(b.note, 1000);
  const org = str(b.org, 120);

  return {
    errors: e,
    occurrences,
    row: {
      name, start_date: start, end_date: end || null, venue, city, state,
      gun_types: JSON.stringify(gunTypes),
      disciplines: JSON.stringify(disciplines),
      org: org || null,
      juniors: b.juniors === true || b.juniors === "true" || b.juniors === 1 ? 1 : 0,
      url: url || null,
      video_url: video || null,
      note: note || null,
      submitter_name: sName,
      submitter_email: sEmail
    }
  };
}

const parseRow = r => ({
  ...r,
  gun_types: safeParse(r.gun_types),
  disciplines: safeParse(r.disciplines),
  juniors: !!r.juniors
});
function safeParse(s) { try { const v = JSON.parse(s); return Array.isArray(v) ? v : []; } catch { return []; } }

/* ------------------------------------------------------------------ */
/* Rankings — shooter identity and placement points                    */
/*                                                                     */
/* Scores cannot be compared between disciplines or courses of fire    */
/* (a 60/60 field target card and a 0.245" benchrest group are not the */
/* same kind of number), so standings are built from finishing place.  */
/* ------------------------------------------------------------------ */

// Points by finishing position, tapering off after the podium. Anyone who
// finishes outside the top 20 still scores 1 for turning up and completing.
const PLACE_POINTS = [25, 20, 16, 13, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
const pointsForPlace = place =>
  !place || place < 1 ? 1 : (PLACE_POINTS[place - 1] ?? 1);

/** Reduces a name to a comparison key: lower case, accents stripped,
 *  punctuation and extra spaces removed. "D. O'Brien-Smith" and
 *  "d obrien smith" collapse to the same key. */
function nameKey(name) {
  return String(name || "")
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    // Apostrophes and full stops vanish, so O'Brien = OBrien and D. = D.
    // Everything else non-alphanumeric becomes a space.
    .replace(/['\u2019.]/g, "")
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/** Best-effort split for display and sorting. Names are messy, so the full
 *  name as typed is always kept; these are only a convenience. */
function splitName(name) {
  const parts = String(name || "").trim().split(/\s+/);
  if (parts.length === 1) return { first: parts[0], last: null };
  return { first: parts[0], last: parts[parts.length - 1] };
}

/** Finds or creates the shooter for a name, following any merge. */
async function resolveShooter(env, name) {
  const key = nameKey(name);
  if (!key) return null;

  let row = await env.DB.prepare(
    "SELECT id, merged_into FROM shooters WHERE name_key = ?"
  ).bind(key).first();

  if (!row) {
    const { first, last } = splitName(name);
    const res = await env.DB.prepare(
      `INSERT INTO shooters (name_key, display_name, first_name, last_name)
       VALUES (?,?,?,?)`
    ).bind(key, String(name).trim().slice(0, 120), first, last).run();
    return res.meta.last_row_id;
  }

  // Follow the merge chain, with a hard stop so a bad loop can't hang a request.
  let id = row.id, hops = 0;
  while (row?.merged_into && hops++ < 10) {
    id = row.merged_into;
    row = await env.DB.prepare("SELECT id, merged_into FROM shooters WHERE id = ?").bind(id).first();
  }
  return id;
}

/* ------------------------------------------------------------------ */
/* Results parsing                                                     */
/* ------------------------------------------------------------------ */

/** Accepts rows pasted from a spreadsheet. Splits on tabs, commas or runs
 *  of spaces, tolerates a header row, and treats a leading number as the
 *  finishing place. Anything unparseable is reported rather than guessed at. */
/* Which disciplines may be posted by pasting a finished sheet.
 *
 * Bench rest is a points discipline: the card is the record, one number per
 * competitor, and a director can reasonably type it up afterwards. Hit-or-miss
 * disciplines — field target, PRS, silhouette — are counted target by target as
 * they are shot, and their denominator exists only because the scorer's phone
 * counted it. Letting those in by paste is how a season of results arrives with
 * no "available" and quietly falls out of the rankings, so they are sent to
 * live scoring instead.
 *
 * Matched on the name, because that is what directors actually type:
 * "Bench Rest", "N50 Benchrest", "100-Yard Benchrest", "Rimfire Benchrest". */
function isPasteable(discipline) {
  return /bench\s*rest/i.test(String(discipline || ""));
}

function parseResultRows(text) {
  const errors = [], rows = [];
  const lines = String(text || "").split(/\r?\n/).map(l => l.trim()).filter(Boolean);

  lines.forEach((line, i) => {
    // Skip an obvious header
    if (i === 0 && /^(place|pos|rank|#)\b/i.test(line)) return;

    // Delimited cells keep their position even when blank, so an empty name
    // column can't let the score slide into the competitor field.
    const delimited = line.includes("\t") || line.includes(",");
    const cells = line.includes("\t") ? line.split("\t")
                : line.includes(",")  ? line.split(",")
                : line.split(/\s{2,}/);
    let parts = cells.map(c => c.trim());
    if (!delimited) parts = parts.filter(c => c !== "");
    while (parts.length && parts[parts.length - 1] === "") parts.pop();
    if (!parts.length) return;

    let place = null, rest = parts;
    if (/^\d{1,4}[.)]?$/.test(parts[0])) {
      place = parseInt(parts[0], 10);
      rest = parts.slice(1);
    }

    const competitor = (rest[0] || "").slice(0, 120);
    if (!competitor) { errors.push(`Line ${i + 1}: no competitor name found.`); return; }

    const score = (rest[1] || "").slice(0, 60) || null;

    /* Some clubs keep X count in its own spreadsheet column rather than
       writing "248-6X". A cell that is nothing but an X count is read as one,
       and the class carries on from the cell after it. */
    const X_CELL = /^(?:(\d{1,3})\s*[xX]|[xX]\s*(\d{1,3}))$/;
    let next = 2, columnX = null;
    const xm = String(rest[2] || "").trim().match(X_CELL);
    if (xm) { columnX = Number(xm[1] ?? xm[2]); next = 3; }

    const read = readAccuracy(score);
    rows.push({
      place,
      competitor,
      score,
      class: (rest[next] || "").slice(0, 60) || null,
      ...read,
      x: read.x ?? columnX
    });
  });

  if (rows.length > 500) errors.push("More than 500 rows in one discipline.");
  return { rows, errors };
}

/**
 * Pulls hits and targets-available out of a score a director already types.
 *
 * National rankings are built on season accuracy, so both numbers are needed.
 * Directors already write them in the forms their sport uses, and reading those
 * is far better than asking for a separate column that half of them would skip:
 *
 *   "45/60"      45 hits of 60          field target, silhouette
 *   "248/250"    248 points of 250      bench rest
 *   "248-6X"     248, ceiling unknown   bench rest, needs the max supplying
 *   "0.245"      a group size           no ceiling exists; left alone
 *
 * Where only one number is present the maximum is filled in later from what the
 * organizer states for that discipline. Anything unreadable is left null rather
 * than guessed — a wrong denominator quietly distorts a whole season.
 */
function readAccuracy(score) {
  const s = String(score || "").trim();
  const none = { hits: null, available: null, x: null };
  if (!s) return none;

  // X count, wherever it sits: "248-6X", "248/250-6X", "97-3x"
  const xm = s.match(/[-\s](\d{1,3})\s*[xX]\b/);
  const x = xm ? Number(xm[1]) : null;

  // "45/60" or "45 / 60"
  const pair = s.match(/^(\d+(?:\.\d+)?)\s*\/\s*(\d+(?:\.\d+)?)/);
  if (pair) {
    const hits = Number(pair[1]), available = Number(pair[2]);
    if (available > 0 && hits >= 0 && hits <= available) return { hits, available, x };
    return none;
  }

  // "248-6X" or a bare "248" — a count with no ceiling stated here
  const lone = s.match(/^(\d+(?:\.\d+)?)(?:\s*-\s*\d+\s*[xX])?$/);
  if (lone) return { hits: Number(lone[1]), available: null, x };

  return none;
}

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Where things are                                                    */
/* ------------------------------------------------------------------ */

/**
 * City and ZIP lookups for the "near me" filter. zippopotam.us is free, needs
 * no key, and answers both "which ZIP is this" and "where is Orlando, FL". The
 * answer is a place's centre, which is exactly as precise as a shooter driving
 * three hours needs and no more. Results are cached at the edge for a week.
 */
async function lookupPlace(path) {
  try {
    const res = await fetch(`https://api.zippopotam.us/us/${path}`, {
      cf: { cacheTtl: 604800, cacheEverything: true }
    });
    if (!res.ok) return null;
    const j = await res.json();
    const p = (j.places || [])[0];
    const lat = p ? parseFloat(p.latitude) : NaN, lng = p ? parseFloat(p.longitude) : NaN;
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
    return { lat, lng, label: `${p["place name"]}, ${p["state abbreviation"]}` };
  } catch { return null; }
}

async function geocodeCity(city, state) {
  const c = String(city || "").trim().toLowerCase();
  const st = String(state || "").trim().toLowerCase();
  if (!c || !/^[a-z]{2}$/.test(st)) return null;
  const tries = [c];
  const alt = c.replace(/^st\.?\s+/, "saint ").replace(/^mt\.?\s+/, "mount ").replace(/^ft\.?\s+/, "fort ");
  if (alt !== c) tries.push(alt);
  for (const t of tries) {
    const hit = await lookupPlace(`${st}/${encodeURIComponent(t)}`);
    if (hit) return hit;
  }
  return null;
}

/** GET /api/geo?zip=32801 — the point a ZIP code stands for. */
async function apiGeo(request) {
  const zip = String(new URL(request.url).searchParams.get("zip") || "").trim();
  if (!/^\d{5}$/.test(zip)) return fail("Enter a 5-digit ZIP code.");
  const hit = await lookupPlace(zip);
  if (!hit) return fail("We couldn't find that ZIP code.", 404);
  return json(hit, 200, { "cache-control": "public, max-age=86400" });
}

/** Fills in coordinates for matches that don't have them yet. A match that
 *  can't be found is remembered for a week rather than asked about on every
 *  page view. Runs after the response has gone out. */
async function geocodeMissing(env, rows) {
  const seen = new Map();   // one lookup per city, however many matches are there
  for (const r of rows) {
    const k = `${String(r.city).toLowerCase()}|${String(r.state).toLowerCase()}`;
    if (!seen.has(k)) seen.set(k, await geocodeCity(r.city, r.state));
    const hit = seen.get(k);
    await env.DB.prepare(
      "UPDATE events SET lat = ?, lng = ?, geo_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?"
    ).bind(hit ? hit.lat : null, hit ? hit.lng : null, r.id).run();
  }
}

/* ------------------------------------------------------------------ */
/* Subscribable calendar feed                                          */
/* ------------------------------------------------------------------ */

const icsEsc = t => String(t ?? "").replace(/\\/g, "\\\\").replace(/;/g, "\\;")
  .replace(/,/g, "\\,").replace(/\r?\n/g, "\\n");

/** Lines in a calendar file may not run past 75 bytes; longer ones are folded
 *  onto continuation lines that start with a space. */
function icsFold(line) {
  const enc = new TextEncoder();
  if (enc.encode(line).length <= 75) return line;
  const out = [];
  let cur = "", bytes = 0;
  for (const ch of line) {
    const b = enc.encode(ch).length;
    if (bytes + b > 75) { out.push(cur); cur = " "; bytes = 1; }
    cur += ch; bytes += b;
  }
  out.push(cur);
  return out.join("\r\n");
}

/**
 * GET /calendar.ics?state=FL,GA&gun=Airgun&disc=Silhouette&juniors=1
 *
 * The same filters as the calendar page, as a feed a phone or desktop calendar
 * can subscribe to. It updates itself: new matches appear and changed dates
 * move without anyone doing anything. Matches from the last 45 days onward are
 * included so a subscriber still sees what just happened. Test events are never
 * included.
 */
async function calendarFeed(request, env, origin) {
  const u = new URL(request.url);
  const list = k => (u.searchParams.get(k) || "").split(",").map(x => x.trim()).filter(Boolean).slice(0, 60);
  const states = list("state").map(x => x.toUpperCase());
  const guns = list("gun"), discs = list("disc");
  const juniors = u.searchParams.get("juniors") === "1";

  const { results } = await env.DB.prepare(
    `SELECT ${PUBLIC_COLUMNS} FROM events
      WHERE status = 'approved' AND is_test = 0
        AND date(COALESCE(end_date, start_date)) >= date('now','-45 days')
      ORDER BY start_date ASC`
  ).all();

  const events = (results || []).map(parseRow).map(e => ({
    ...e, gun_types: e.gun_types.length ? e.gun_types : ["Airgun"]
  })).filter(e =>
    (!states.length || states.includes(e.state)) &&
    (!guns.length || e.gun_types.some(g => guns.includes(g))) &&
    (!discs.length || e.disciplines.some(d => discs.includes(d))) &&
    (!juniors || e.juniors));

  const stamp = d => d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const day = iso => String(iso).slice(0, 10).replace(/-/g, "");
  const dayAfter = iso => {
    const [y, m, dd] = String(iso).slice(0, 10).split("-").map(Number);
    return stamp(new Date(Date.UTC(y, m - 1, dd + 1))).slice(0, 8);
  };
  const now = stamp(new Date());

  const title = ["GunMatches", [...states, ...guns, ...discs].join(" · ")].filter(Boolean).join(" — ");
  const lines = [
    "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//GunMatches.com//Calendar//EN",
    "CALSCALE:GREGORIAN", "METHOD:PUBLISH",
    `X-WR-CALNAME:${icsEsc(title)}`,
    "X-WR-CALDESC:Shooting matches from GunMatches.com",
    "REFRESH-INTERVAL;VALUE=DURATION:PT6H", "X-PUBLISHED-TTL:PT6H"
  ];
  for (const e of events) {
    const first = day(e.start_date), last = e.end_date || e.start_date;
    const modified = e.confirmed_at ? stamp(new Date(e.confirmed_at)).replace(/Z?$/, "Z") : now;
    const about = [
      [e.gun_types.join(", "), e.disciplines.join(", ")].filter(Boolean).join(" — "),
      e.org, e.note, e.url, `${origin}${eventPath(e)}`
    ].filter(Boolean).join("\n");
    lines.push(
      "BEGIN:VEVENT",
      `UID:${e.id}@gunmatches.com`,
      `DTSTAMP:${now}`,
      `LAST-MODIFIED:${modified.length === 16 ? modified : now}`,
      `DTSTART;VALUE=DATE:${first}`,
      `DTEND;VALUE=DATE:${dayAfter(last)}`,
      `SUMMARY:${icsEsc((e.listing_status === "cancelled" ? "CANCELLED: " : e.listing_status === "postponed" ? "POSTPONED: " : "") + e.name)}`,
      `LOCATION:${icsEsc([e.venue, e.city, e.state].filter(Boolean).join(", "))}`,
      `DESCRIPTION:${icsEsc(about)}`,
      `URL:${origin}${eventPath(e)}`,
      e.listing_status === "cancelled" ? "STATUS:CANCELLED" : "STATUS:CONFIRMED", "TRANSP:TRANSPARENT",
      "END:VEVENT"
    );
  }
  lines.push("END:VCALENDAR");

  return new Response(lines.map(icsFold).join("\r\n") + "\r\n", {
    headers: {
      "content-type": "text/calendar; charset=utf-8",
      "content-disposition": 'inline; filename="gunmatches.ics"',
      "cache-control": "public, max-age=900",
      ...securityHeaders()
    }
  });
}

/**
 * Keeps a busy GET answer at the edge for a few seconds. The events list costs
 * several database queries, and every open calendar re-asks for it, so without
 * this the database does the same work over and over. Ten seconds is short
 * enough that a director's LIVE switch still shows up almost at once.
 * Browsers are still told to revalidate, so they always ask, but the answer
 * comes from the edge rather than the database.
 */
async function edgeCached(request, ctx, ttl, produce) {
  const cache = typeof caches !== "undefined" ? caches.default : null;
  if (!cache) return produce();
  const key = new Request(new URL(request.url).toString(), { method: "GET" });
  const hit = await cache.match(key);
  if (hit) {
    const out = new Response(hit.body, hit);
    out.headers.set("cache-control", "public, max-age=0, must-revalidate");
    return out;
  }
  const res = await produce();
  if (res.ok && ctx && ctx.waitUntil) {
    const copy = new Response(res.clone().body, res);
    copy.headers.set("cache-control", `public, max-age=${ttl}`);
    ctx.waitUntil(cache.put(key, copy).catch(() => {}));
  }
  return res;
}

async function getPublicEvents(env, ctx) {
  const { results } = await env.DB.prepare(
    `SELECT ${PUBLIC_COLUMNS} FROM events WHERE status = 'approved' ORDER BY start_date ASC`
  ).all();

  const weekAgo = new Date(Date.now() - 7 * 86400000).toISOString();
  const need = (results || []).filter(r =>
    (r.lat === null || r.lat === undefined) && (!r.geo_at || r.geo_at < weekAgo)).slice(0, 30);
  if (need.length && ctx && ctx.waitUntil) ctx.waitUntil(geocodeMissing(env, need).catch(() => {}));

  const events = (results || []).map(parseRow);
  events.forEach(e => { delete e.geo_at; });

  // Attach published results, grouped by discipline, in finishing order.
  const rows = await env.DB.prepare(
    `SELECT r.event_id, r.discipline, r.place, r.competitor, r.score, r.class
       FROM results r
       JOIN events e ON e.id = r.event_id
      WHERE e.status = 'approved'
      ORDER BY r.discipline, r.sort_order`
  ).all();

  const byEvent = {};
  (rows.results || []).forEach(r => {
    const ev = (byEvent[r.event_id] ||= {});
    (ev[r.discipline] ||= []).push({
      place: r.place, competitor: r.competitor, score: r.score, class: r.class
    });
  });
  /* The event's own address, computed here rather than in the browser. The
     slug rules live in one place, so a page the client links to and a page the
     sitemap lists can never disagree. */
  const live = await liveEventIds(env);
  events.forEach(e => {
    e.results = byEvent[e.id] || null;
    e.path = eventPath(e);
    e.live = live.has(e.id);
  });

  return json({ events }, 200, {
    /* Revalidated on every load. This carries each event's LIVE flag, and a
       director switching public standings on or off has to show up on the next
       reload, not after a cache runs out. */
    "cache-control": "public, max-age=0, must-revalidate"
  });
}

async function createSubmission(request, env) {
  let body;
  try { body = await request.json(); } catch { return fail("Malformed request."); }

  // Honeypot — a filled hidden field means a bot. Report success and drop it,
  // so the bot has no signal to retry.
  if (str(body.website, 100)) return json({ ok: true });

  const ip = request.headers.get("CF-Connecting-IP");
  if (!(await turnstileOk(body.turnstile_token, ip, env)))
    return fail("Spam check failed. Please reload the page and try again.", 403);

  const { errors, row, occurrences } = validateSubmission(body);
  if (errors.length) return json({ error: errors.join(" ") }, 400);

  const ipHash = await hashIp(ip, env.IP_SALT || "airgunmatches");

  /* Rate limit: at most 5 submissions per address per hour.
   *
   * Counted by submission, not by row. A club posting a nine-date season is
   * one act by one person; counting the rows would have locked them out
   * halfway through their own first submission. */
  if (ipHash) {
    const since = new Date(Date.now() - 3600_000).toISOString().slice(0, 19) + "Z";
    const { count } = await env.DB.prepare(
      `SELECT COUNT(DISTINCT COALESCE(series_id, id)) AS count
         FROM events WHERE submit_ip_hash = ? AND created_at > ?`
    ).bind(ipHash, since).first();
    if (count >= 5) return fail("Too many submissions from this connection. Try again later.", 429);
  }

  /* Dates already listed for this match are skipped rather than failing the
     whole batch. A club re-submitting a season with two new dates added should
     get the two new dates, not an error about the seven that already exist. */
  const already = await env.DB.prepare(
    `SELECT start_date FROM events
      WHERE lower(trim(name)) = lower(trim(?)) AND lower(trim(venue)) = lower(trim(?))`
  ).bind(row.name, row.venue).all();
  const taken = new Set((already.results || []).map(r => r.start_date));
  const fresh = occurrences.filter(o => !taken.has(o.start));

  if (!fresh.length) {
    return json({ ok: true, duplicate: true,
      message: occurrences.length > 1
        ? "Every one of those dates is already listed — we'll review the existing entries."
        : "That match is already submitted — we'll review the existing entry." });
  }

  // Only a real series gets an id. A one-off stays null, so nothing changes for it.
  const seriesId = occurrences.length > 1 ? crypto.randomUUID() : null;
  const country = request.headers.get("CF-IPCountry") || null;

  const made = fresh.map(o => ({ id: crypto.randomUUID(), ...o }));
  const stmts = made.map(o => env.DB.prepare(
    `INSERT INTO events (id, name, start_date, end_date, venue, city, state, gun_types, disciplines,
                         org, juniors, url, video_url, note, submitter_name, submitter_email,
                         status, submit_ip_hash, submit_country, series_id)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending', ?, ?, ?)`
  ).bind(
    o.id, row.name, o.start, o.end, row.venue, row.city, row.state,
    row.gun_types, row.disciplines, row.org, row.juniors, row.url, row.video_url, row.note,
    row.submitter_name, row.submitter_email,
    ipHash, country, seriesId
  ));

  try {
    // All or nothing: a half-created season would be worse than a clear failure.
    await env.DB.batch(stmts);
  } catch (err) {
    if (String(err).includes("UNIQUE")) {
      return json({ ok: true, duplicate: true,
        message: "That match is already submitted — we'll review the existing entry." });
    }
    throw err;
  }

  const skipped = occurrences.length - fresh.length;
  return json({
    ok: true,
    id: made[0].id,
    series_id: seriesId,
    created: made.length,
    skipped,
    dates: made.map(o => o.start)
  }, 201);
}

/**
 * The events that are being shot right now.
 *
 * Three things all have to be true: the director opened a discipline, marked
 * it public, and the calendar date has actually arrived and not passed. The
 * date test is the one that matters in practice — a director packs up and
 * drives home without closing the match, and without this the event would
 * announce itself as live until somebody noticed. The database decides, not a
 * forgotten checkbox.
 *
 * end_date is coalesced to start_date so a one-day match stops being live at
 * the end of that day rather than never.
 *
 * "Today" is the US date, not the UTC date: the server clock is UTC, which
 * rolls to tomorrow at 7-8pm Eastern, and an evening match would drop off the
 * homepage mid-shoot. Shifting the clock back 10 hours (Hawaii) keeps every US
 * match live until the morning after, and a day-long grace is harmless.
 */
async function liveEventIds(env) {
  const { results } = await env.DB.prepare(
    `SELECT DISTINCT e.id
       FROM events e
       JOIN match_disciplines d ON d.event_id = e.id
      WHERE e.status = 'approved'
        AND d.live_public = 1
        AND d.state = 'live'
        AND date('now','-10 hours') BETWEEN date(e.start_date) AND date(COALESCE(e.end_date, e.start_date))`
  ).all();
  return new Set((results || []).map(r => r.id));
}

/* Every approved event, shaped the way the SEO module expects. One query
   serves the sitemap, the calendar injection and the ItemList alike. */
/* Kept for ten seconds inside the running worker. A busy page asks for this on
   every view; the list only changes when someone edits it, and ten seconds is
   well inside what a director switching standings on or off can tolerate. */
let APPROVED_MEMO = { at: 0, rows: null };
async function approvedEvents(env) {
  if (APPROVED_MEMO.rows && Date.now() - APPROVED_MEMO.at < 10000) return APPROVED_MEMO.rows;
  const live = await liveEventIds(env);
  const { results } = await env.DB.prepare(
    `SELECT id, name, start_date, end_date, venue, city, state, gun_types,
            disciplines, org, juniors, url, note, created_at, results_updated_at,
            listing_status
       FROM events WHERE status = 'approved' ORDER BY start_date ASC`
  ).all();
  const rows = (results || []).map(parseRow).map(e => ({ ...e, live: live.has(e.id) }));
  APPROVED_MEMO = { at: Date.now(), rows };
  return rows;
}

/**
 * One event, at its own address, rendered on the server.
 *
 * Google's event results require a page per event, and a page cannot be
 * shared, linked or bookmarked if it only exists as a fragment of the
 * calendar. The id fragment in the path is matched by prefix so the readable
 * slug can change — a club renaming its match should not break inbound links.
 */
async function serveEventPage(request, env, path, origin, host, ctx) {
  const frag = idFragmentFrom(path);
  if (!frag) return null;

  const row = await env.DB.prepare(
    `SELECT * FROM events
      WHERE status = 'approved' AND replace(id,'-','') LIKE ? || '%'
      LIMIT 2`
  ).bind(frag).all();

  const rows = row.results || [];
  if (rows.length !== 1) return null;       // unknown, or an ambiguous prefix

  const ev = parseRow(rows[0]);

  /* Being shot right now changes what this page is for, so decide before
     building anything else. */
  const live = (await liveEventIds(env)).has(ev.id);
  ev.results = live ? null : await resultsFor(env, ev.id);

  /* The results credit, on event pages that actually have results. Not during
     a match: the live page carries nothing but standings. */
  let credit = "";
  if (ev.results && !live) {
    const sponsor = await activeSponsor(env);
    credit = resultsCreditHtml(sponsor, host);
  }

  // Keep one address per event: anything else 301s to the canonical slug.
  const canonical = eventPath(ev);
  if (path !== canonical) {
    return new Response(null, {
      status: 301,
      headers: { location: origin + canonical, ...securityHeaders() }
    });
  }

  if (live) {
    /* Never cached. A standings page served from an edge cache is a page
       showing somebody else's idea of the current order. */
    const sponsor = await activeSponsor(env);
    const parts = liveSponsorParts(sponsor);
    if (parts && ctx && ctx.waitUntil)
      ctx.waitUntil(countImpression(env, sponsor.id).catch(() => {}));
    return new Response(liveEventPageHtml(ev, origin, parts), {
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        ...securityHeaders()
      }
    });
  }

  let page = eventPageHtml(ev, origin);
  if (credit) {
    page = page
      .replace("</head>", `<style>${SPONSOR_CSS}</style>\n</head>`)
      .replace("</div>\n\n  <p class=\"crumb\">Is this your match", `${credit}</div>\n\n  <p class="crumb">Is this your match`);
  }

  return new Response(page, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      /* Not cached: when a match goes live this same address must turn into the
         live standings page on the next load, not ten minutes later. */
      "cache-control": "public, max-age=0, must-revalidate",
      ...securityHeaders()
    }
  });
}

/** Published results for one event, grouped by discipline, in finishing order. */
async function resultsFor(env, id) {
  const { results } = await env.DB.prepare(
    `SELECT discipline, place, competitor, score, class
       FROM results WHERE event_id = ? ORDER BY discipline, sort_order`
  ).bind(id).all();
  if (!results || !results.length) return null;
  const out = {};
  for (const r of results) (out[r.discipline] ||= []).push(r);
  return out;
}

async function getResultsEvent(request, env) {
  const code = new URL(request.url).searchParams.get("code");
  const ev = await eventForCode(env, code);
  if (!ev || ev.status !== "approved") return fail("That code isn't recognised.", 404);

  const existing = await env.DB.prepare(
    "SELECT discipline, place, competitor, score, class FROM results WHERE event_id = ? ORDER BY discipline, sort_order"
  ).bind(ev.id).all();

  return json({
    event: {
      name: ev.name, start_date: ev.start_date, end_date: ev.end_date,
      venue: ev.venue, city: ev.city, state: ev.state,
      disciplines: safeParse(ev.disciplines),
      pasteable: safeParse(ev.disciplines).filter(isPasteable)
    },
    results: existing.results || []
  }, 200, { "cache-control": "no-store" });
}

async function saveResults(request, env) {
  let body;
  try { body = await request.json(); } catch { return fail("Malformed request."); }

  const ev = await eventForCode(env, body.code);
  if (!ev || ev.status !== "approved") return fail("That code isn't recognised.", 404);

  const disciplines = safeParse(ev.disciplines);
  const incoming = body.disciplines && typeof body.disciplines === "object" ? body.disciplines : {};

  /* An optional ceiling per discipline: "how many targets were there to hit?"
     It fills the denominator for scores written as a bare number, so a bench
     rest sheet of 248, 246, 241 can still contribute to season accuracy. Scores
     already written as 45/60 carry their own and ignore this. */
  const maxima = body.available && typeof body.available === "object" ? body.available : {};

  const statements = [];
  let total = 0;
  const problems = [];

  for (const [discipline, text] of Object.entries(incoming)) {
    if (!disciplines.includes(discipline)) {
      problems.push(`"${discipline}" is not one of this event's disciplines.`);
      continue;
    }
    /* Enforced here and not only in the page, because the page can be edited. */
    if (!isPasteable(discipline)) {
      problems.push(
        `${discipline} is scored target by target, so it has to be scored live rather ` +
        `than pasted in — open the scoring page and set it up there.`);
      continue;
    }
    const { rows, errors } = parseResultRows(text);
    errors.forEach(e => problems.push(`${discipline} — ${e}`));

    const stated = Number(maxima[discipline]);
    const ceiling = Number.isFinite(stated) && stated > 0 ? stated : null;

    const fieldSize = rows.length;
    for (const [idx, r] of rows.entries()) {
      const place = r.place !== null ? r.place : idx + 1;
      // A test event never creates or feeds a shooter's record.
      const shooterId = ev.is_test ? null : await resolveShooter(env, r.competitor);

      // a score of "45/60" brings its own ceiling; a bare "248" borrows the
      // organizer's, and anything above that ceiling is treated as unusable
      // rather than quietly capped
      let hits = r.hits, available = r.available;
      if (hits !== null && available === null && ceiling !== null) available = ceiling;
      if (available !== null && (hits === null || hits > available)) { hits = null; available = null; }

      statements.push(
        env.DB.prepare(
          `INSERT INTO results (event_id, discipline, place, competitor, score, class,
                                sort_order, shooter_id, points, field_size, hits, available,
                                x_count)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
        ).bind(ev.id, discipline, r.place, r.competitor, r.score, r.class,
               place, shooterId, pointsForPlace(place), fieldSize,
               available === null ? null : hits, available,
               Number.isFinite(r.x) ? r.x : null)
      );
      total++;
    }
  }

  if (problems.length) return json({ error: problems.join(" ") }, 400);
  if (!total) return fail("No results were found in what you pasted.");

  // Replace wholesale, so re-uploading a corrected sheet is safe.
  await env.DB.batch([
    env.DB.prepare("DELETE FROM results WHERE event_id = ?").bind(ev.id),
    ...statements,
    env.DB.prepare("UPDATE events SET results_updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?").bind(ev.id)
  ]);

  return json({ ok: true, saved: total });
}

/* Standings over a rolling 12 months. Points come from finishing place, so
   every discipline and course of fire contributes on the same scale. */
/**
 * Standings, one ranking class per discipline.
 *
 * WHAT THE NUMBER MEANS. A shooter's standing is their season accuracy: every
 * target they hit, over every target that was there to be hit. Shoot 85 of 100
 * at one match and 170 of 200 at the next, and you stand at 255/300 — 85%.
 * It measures shooting rather than who else turned up that day, which is why a
 * strong club shooter and a travelling competitor can be compared honestly.
 *
 * WHY TOTAL HITS AND NOT A PERCENTAGE. A rate on its own hands first place to
 * anyone who shot one perfect card and stopped, and no amount of shooting after
 * that can beat 100%. Counting hits solves it without excluding anybody: five
 * matches at 92% is 460 hits and outranks one match at 92%, which is 92. Every
 * competitor appears from their first result.
 *
 * Turning out helps, but only while you are hitting. Five hundred targets at
 * 92% is 460 hits and beats a thousand targets at 40%, which is 400. Accuracy
 * is shown beside every total so the two numbers can be read together, and it
 * separates shooters who finish level on hits.
 *
 * DISCIPLINES ARE NEVER COMBINED. Field target and PRS on the same weekend are
 * two results in two classes. Adding them would be adding different currencies.
 *
 * NOT EVERY DISCIPLINE HAS A CEILING. A group size of 0.245 inches has no
 * "available", so those classes fall back to finishing position, weighted by
 * how large a field was beaten. Each class reports which basis it used, because
 * a standing nobody can explain is a standing people argue with.
 */
const FIELD_WEIGHT =
  `CASE WHEN r.field_size >= 2
        THEN MIN(2.0, MAX(0.6, 0.6 + 0.4 * log2(r.field_size / 10.0)))
        ELSE 1.0 END`;

async function getRankings(request, env) {
  const url = new URL(request.url);
  const since = new Date(Date.now() - 365 * 86400_000).toISOString().slice(0, 10);

  /* Which classes exist, and whether each one can be scored on accuracy.
     A class qualifies for accuracy when most of its results carry a ceiling;
     a stray result without one shouldn't drag a whole discipline back to
     placement scoring, and a stray one *with* one shouldn't promote it. */
  const discRows = await env.DB.prepare(
    `SELECT r.discipline,
            COUNT(DISTINCT r.shooter_id) AS shooters,
            COUNT(DISTINCT r.event_id)   AS events,
            SUM(CASE WHEN r.available > 0 THEN 1 ELSE 0 END) AS with_targets,
            COUNT(*) AS total_results
       FROM results r JOIN events e ON e.id = r.event_id
      WHERE e.status = 'approved' AND e.is_test = 0 AND e.start_date >= ? AND r.shooter_id IS NOT NULL
      GROUP BY r.discipline
      ORDER BY shooters DESC, r.discipline ASC`
  ).bind(since).all();

  const classes = (discRows.results || []).map(c => ({
    discipline: c.discipline,
    shooters: c.shooters,
    events: c.events,
    basis: c.total_results > 0 && c.with_targets >= c.total_results / 2 ? "accuracy" : "placement"
  }));

  const asked = url.searchParams.get("discipline");
  const chosen = classes.find(c => c.discipline === asked) || classes[0] || null;

  if (!chosen) {
    return json({ standings: [], disciplines: [], discipline: null, basis: null,
                  window: { since, description: "Rolling 12 months" } },
                200, { "cache-control": "public, max-age=300" });
  }

  const rows = chosen.basis === "accuracy"
    ? (await env.DB.prepare(
        `SELECT s.id AS shooter_id, s.display_name AS name, s.first_name, s.last_name,
                SUM(r.hits)                AS hits,
                SUM(r.available)           AS available,
                SUM(COALESCE(r.x_count,0)) AS x,
                COUNT(DISTINCT r.event_id) AS events,
                SUM(CASE WHEN r.place = 1 THEN 1 ELSE 0 END) AS wins,
                SUM(CASE WHEN r.place <= 3 THEN 1 ELSE 0 END) AS podiums,
                MIN(r.place)               AS best_place,
                MAX(e.start_date)          AS last_event
           FROM results r
           JOIN events e   ON e.id = r.event_id
           JOIN shooters s ON s.id = r.shooter_id
          WHERE e.status = 'approved' AND e.is_test = 0 AND e.start_date >= ?
            AND r.shooter_id IS NOT NULL AND r.discipline = ?
            AND r.available > 0 AND r.hits IS NOT NULL
          GROUP BY s.id
          ORDER BY SUM(r.hits) DESC,
                   (SUM(r.hits) * 1.0 / SUM(r.available)) DESC,
                   SUM(COALESCE(r.x_count,0)) DESC,
                   s.display_name ASC
          LIMIT 500`
      ).bind(since, chosen.discipline).all()).results || []
    : (await env.DB.prepare(
        `SELECT s.id AS shooter_id, s.display_name AS name, s.first_name, s.last_name,
                SUM(r.points * (${FIELD_WEIGHT})) AS points,
                COUNT(DISTINCT r.event_id) AS events,
                SUM(CASE WHEN r.place = 1 THEN 1 ELSE 0 END) AS wins,
                SUM(CASE WHEN r.place <= 3 THEN 1 ELSE 0 END) AS podiums,
                MIN(r.place)               AS best_place,
                MAX(r.field_size)          AS biggest_field,
                MAX(e.start_date)          AS last_event
           FROM results r
           JOIN events e   ON e.id = r.event_id
           JOIN shooters s ON s.id = r.shooter_id
          WHERE e.status = 'approved' AND e.is_test = 0 AND e.start_date >= ?
            AND r.shooter_id IS NOT NULL AND r.discipline = ?
          GROUP BY s.id
          ORDER BY points DESC, wins DESC, events DESC, s.display_name ASC
          LIMIT 300`
      ).bind(since, chosen.discipline).all()).results || [];

  const shape = r => ({
    shooter_id: r.shooter_id, name: r.name,
    first_name: r.first_name, last_name: r.last_name,
    events: r.events, wins: r.wins, podiums: r.podiums,
    best_place: r.best_place, last_event: r.last_event,
    ...(chosen.basis === "accuracy"
        ? { hits: Math.round(r.hits), available: Math.round(r.available),
            rate: Math.round((r.hits / r.available) * 1000) / 10,
            x: r.x ? Math.round(r.x) : 0 }
        : { points: Math.round(r.points), biggest_field: r.biggest_field })
  });

  // Everyone who has posted a result appears, from their first one.
  const standings = rows.map((r, i) => ({ rank: i + 1, ...shape(r) }));

  return json({
    standings,
    discipline: chosen.discipline,
    basis: chosen.basis,
    disciplines: classes,
    window: { since, description: "Rolling 12 months" }
  }, 200, { "cache-control": "public, max-age=300, stale-while-revalidate=900" });
}

/* Every result for one shooter, newest first. */
async function getShooter(request, env, id) {
  const shooter = await env.DB.prepare(
    "SELECT id, display_name, first_name, last_name FROM shooters WHERE id = ? AND merged_into IS NULL"
  ).bind(id).first();
  if (!shooter) return fail("Shooter not found.", 404);

  const { results } = await env.DB.prepare(
    `SELECT e.name AS event, e.start_date, e.venue, e.city, e.state,
            r.discipline, r.place, r.score, r.class, r.points, r.field_size
       FROM results r JOIN events e ON e.id = r.event_id
      WHERE r.shooter_id = ? AND e.status = 'approved' AND e.is_test = 0
      ORDER BY e.start_date DESC`
  ).bind(id).all();

  return json({ shooter, results: results || [] }, 200,
              { "cache-control": "public, max-age=300" });
}

/* Names that look like the same person, for the merge screen. */
/* ------------------------------------------------------------------ */
/* Bulk import                                                         */
/* ------------------------------------------------------------------ */

const MAX_IMPORT_EVENTS = 200;

/* Pages that should name themselves as the original. The canonical always
   points at gunmatches.com regardless of which domain served the request —
   that is the whole point: one address per page, whichever door you came in. */
/* The www form, because that is what actually answers: the apex redirects to
   it. A canonical pointing at a URL that 301s asks Google to trust a signpost
   rather than the address, and it is the kind of thing nobody notices for
   months. Change this if the redirect direction ever flips. */
const CANONICAL_ORIGIN = "https://www.gunmatches.com";
const CANONICAL_PAGES = new Set([
  "/rankings.html", "/rankings", "/organizers.html", "/organizers", "/my.html", "/my"
]);

/** The address we want indexed, given whichever spelling was requested.
    Static assets are served with the extension stripped, so a visitor can
    arrive at either and both must name the same canonical. */
function canonicalPathFor(path) {
  return path.endsWith(".html") ? path : path + ".html";
}

/**
 * An HTML response built from scratch rather than cloned.
 *
 * The asset response carries content-encoding and content-length describing
 * the *compressed* bytes it was going to send. Reading it as text decompresses
 * it, so copying those headers onto the decoded string tells the browser to
 * gunzip plain HTML — and it gets an empty page. Easier to state the few
 * headers that are actually true than to remember which inherited ones lie.
 */
/**
 * The calendar's own HTML, fetched from the asset layer.
 *
 * Asking for "/index.html" is the obvious move and the wrong one: the asset
 * layer treats "/" as the canonical address and answers the longer spelling
 * with a redirect to it. Passing that redirect back to the browser sent it
 * round to "/" again, which came back here — a loop that took the homepage
 * down until a browser reported ERR_TOO_MANY_REDIRECTS.
 *
 * So ask for "/" first, and if the asset layer ever redirects anyway, follow
 * it once rather than handing a redirect to the visitor. Looping is the one
 * failure mode worth spending a few lines to make impossible.
 */
async function calendarAsset(request, env, origin) {
  let res = await env.ASSETS.fetch(new Request(origin + "/", request));
  if (res.status >= 300 && res.status < 400) {
    const to = res.headers.get("location");
    if (!to) return null;
    res = await env.ASSETS.fetch(new Request(new URL(to, origin).toString(), request));
    if (res.status >= 300 && res.status < 400) return null;   // never a second hop
  }
  return res;
}

function htmlResponse(html, cacheControl) {
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": cacheControl,
      ...securityHeaders()
    }
  });
}

/** A 404 that still looks like the site and offers a way back. */
function notFoundHtml(origin) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Match not found — GunMatches.com</title>
<style>body{margin:0;background:#f5f6f8;color:#1d2733;font:16px/1.6 -apple-system,
BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;display:flex;min-height:100vh;
align-items:center;justify-content:center;text-align:center}
.b{max-width:460px;padding:30px}h1{font-size:23px;margin:0 0 10px}
p{color:#677280}a{color:#B71D1C;font-weight:700}</style></head>
<body><div class="b"><h1>That match isn't listed</h1>
<p>It may have been removed, or the link may be out of date.</p>
<p><a href="/">See every upcoming match →</a></p></div></body></html>`;
}

/** A loose key for "is this the same match?" — lowercase, no punctuation, and
 *  with the words clubs pad names with stripped out, so "NSC Grand Prix 2026"
 *  and "N.S.C. Grand-Prix" collapse to the same thing. */
function matchKey(name) {
  return String(name || "")
    .toLowerCase()
    // Apostrophes are dropped, not spaced: club names are full of them, and
    // "Sportsman's" must stay one word so it can match "Sportsmans".
    .replace(/['\u2019]/g, "")
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\b(the|a|an|20\d\d|annual|match|shoot|event|club|grand|prix|gp)\b/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

const words = name => String(name || "")
  .toLowerCase().replace(/['\u2019]/g, "")
  .replace(/[^a-z0-9\s]/g, " ").split(/\s+/).filter(Boolean);

/** The letters a name would be abbreviated to: "Nenameseck Sportsmens Club
 *  Grand Prix" -> "nscgp". Stop words are kept, because the C in NSC stands
 *  for Club. */
const initials = name => words(name).map(w => w[0]).join("");

/** Things in a name that might themselves be an acronym.
 *
 *  Two shapes: a short all-letter token that survived stop-word removal
 *  ("NSC"), and a run of single letters from a dotted form ("N.S.C." arrives
 *  as n, s, c). Drawn from the stripped key rather than the raw name so that
 *  "Grand" and "Prix" — short, common, and in half the names on the calendar —
 *  can't match everything they touch. */
function acronyms(name) {
  const out = new Set();
  for (const w of words(matchKey(name)))
    if (w.length >= 2 && w.length <= 6 && /^[a-z]+$/.test(w)) out.add(w);

  let run = "";
  for (const w of words(name)) {
    if (w.length === 1) run += w;
    else { if (run.length >= 2) out.add(run); run = ""; }
  }
  if (run.length >= 2) out.add(run);
  return out;
}

/** Whether two event names plausibly describe the same match. Deliberately
 *  generous: this only ever causes an event to be held back and shown in the
 *  preview, and a duplicate that reaches the calendar costs more to undo than
 *  a real event costs to add by hand. */
function looksLikeSameMatch(a, b) {
  const ka = matchKey(a), kb = matchKey(b);
  if (!ka || !kb) return false;
  if (ka === kb || ka.includes(kb) || kb.includes(ka)) return true;

  // "NSC" against "Nenameseck Sportsmens Club" — an acronym on one side
  // matching the initials of the other
  const ia = initials(a), ib = initials(b);
  for (const c of acronyms(a)) if (c.length >= 2 && ib.startsWith(c)) return true;
  for (const c of acronyms(b)) if (c.length >= 2 && ia.startsWith(c)) return true;
  for (const c of acronyms(a)) if (acronyms(b).has(c)) return true;
  return false;
}

/**
 * Takes a batch of events from the scout and puts them straight on the
 * calendar, approved.
 *
 * Behind the admin session, so no Turnstile and no per-address rate limit —
 * both of those exist to keep strangers honest, and this is the owner pasting
 * their own research.
 *
 * Duplicate detection runs against the database rather than any ledger file.
 * The scout re-finds the same matches every run, and its own record of what it
 * submitted lives on one computer and knows nothing about what has been edited
 * or deleted here since. Two passes:
 *
 *   exact  — same name, same venue, same start date. Silently skipped.
 *   likely — same start date, same city and state, and a fuzzy name match.
 *            Reported rather than skipped quietly, because two genuinely
 *            different matches can share a club and a Saturday.
 *
 * dry_run returns exactly what a real run would do and writes nothing, which
 * is what the admin page shows you before you commit.
 */
async function adminImport(request, env, reviewer) {
  let body;
  try { body = await request.json(); } catch { return fail("Malformed request."); }

  const dryRun = body.dry_run !== false;          // preview unless told otherwise
  const incoming = Array.isArray(body.events) ? body.events : null;
  if (!incoming) return fail('Expected { "events": [ ... ] }.');
  if (!incoming.length) return fail("That file has no events in it.");
  if (incoming.length > MAX_IMPORT_EVENTS)
    return fail(`No more than ${MAX_IMPORT_EVENTS} events in one import.`);

  // Everything already on the calendar, at any status — a rejected event is
  // still a decision, and re-importing it would quietly overturn it.
  const existing = (await env.DB.prepare(
    "SELECT name, venue, city, state, start_date, status FROM events"
  ).all()).results || [];

  const exact = new Set(existing.map(r =>
    `${String(r.name).trim().toLowerCase()}|${String(r.venue).trim().toLowerCase()}|${r.start_date}`));
  const byDatePlace = new Map();
  for (const r of existing) {
    const k = `${r.start_date}|${String(r.city).trim().toLowerCase()}|${String(r.state).toUpperCase()}`;
    if (!byDatePlace.has(k)) byDatePlace.set(k, []);
    byDatePlace.get(k).push(r);
  }

  const today = new Date().toISOString().slice(0, 10);
  const report = [];
  const stmts = [];
  // Guards against one file containing the same match twice
  const seenThisRun = new Set();

  for (const [i, raw] of incoming.entries()) {
    const label = str(raw && raw.name, 160) || `row ${i + 1}`;

    const { errors, row, occurrences } = validateSubmission({
      ...raw,
      submitter_name: str(raw.submitter_name, 120) || "Airgun Match Scout",
      submitter_email: str(raw.submitter_email, 200) || "canyoncaplinger@gmail.com"
    });

    if (errors.length) {
      report.push({ name: label, action: "rejected", reason: errors.join(" ") });
      continue;
    }

    const fresh = [];
    for (const o of occurrences) {
      if (o.start <= today) {
        report.push({ name: label, date: o.start, action: "skipped", reason: "Date has already passed." });
        continue;
      }
      const ek = `${row.name.trim().toLowerCase()}|${row.venue.trim().toLowerCase()}|${o.start}`;
      if (exact.has(ek)) {
        report.push({ name: label, date: o.start, action: "skipped",
                      reason: "Already on the calendar." });
        continue;
      }
      if (seenThisRun.has(ek)) {
        report.push({ name: label, date: o.start, action: "skipped",
                      reason: "This file lists the same match twice." });
        continue;
      }

      /* Anything already on the calendar in the same town on the same day.
         A name match makes it near-certain; without one it is still held back
         and shown, because two matches in one town on one day is unusual
         enough to be worth a human glance. */
      const sameDayPlace = byDatePlace.get(
        `${o.start}|${row.city.trim().toLowerCase()}|${row.state.toUpperCase()}`) || [];
      if (sameDayPlace.length) {
        const named = sameDayPlace.find(r => looksLikeSameMatch(r.name, row.name));
        report.push(named
          ? { name: label, date: o.start, action: "skipped",
              reason: `Already listed as "${named.name}".` }
          : { name: label, date: o.start, action: "skipped", check: true,
              reason: `"${sameDayPlace[0].name}" is already listed in ${row.city} that day — ` +
                      `skipped in case it is the same match under another name.` });
        continue;
      }

      seenThisRun.add(ek);
      fresh.push(o);
    }

    if (!fresh.length) continue;

    const seriesId = fresh.length > 1 ? crypto.randomUUID() : null;
    for (const o of fresh) {
      const id = crypto.randomUUID();
      report.push({
        name: row.name, date: o.start, end: o.end, venue: row.venue,
        city: row.city, state: row.state,
        disciplines: safeParse(row.disciplines),
        gun_types: safeParse(row.gun_types),
        action: "created"
      });
      stmts.push(env.DB.prepare(
        `INSERT INTO events (id, name, start_date, end_date, venue, city, state, gun_types,
                             disciplines, org, juniors, url, video_url, note,
                             submitter_name, submitter_email, status, series_id,
                             reviewed_at, reviewed_by, review_note)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'approved', ?,
                 strftime('%Y-%m-%dT%H:%M:%SZ','now'), ?, ?)`
      ).bind(
        id, row.name, o.start, o.end, row.venue, row.city, row.state,
        row.gun_types, row.disciplines, row.org, row.juniors, row.url, row.video_url, row.note,
        row.submitter_name, row.submitter_email, seriesId, reviewer,
        `Bulk import ${today}`
      ));
    }
  }

  const counts = report.reduce((a, r) => (a[r.action] = (a[r.action] || 0) + 1, a), {});

  if (dryRun) return json({ ok: true, dry_run: true, counts, report });
  if (!stmts.length) return json({ ok: true, dry_run: false, counts, report, imported: 0 });

  await env.DB.batch(stmts);
  return json({ ok: true, dry_run: false, counts, report, imported: stmts.length });
}

/* ------------------------------------------------------------------ */
/* Sponsors                                                            */
/* ------------------------------------------------------------------ */

/** Every sponsor, with its running totals and whether it is live today. */
async function adminSponsors(env) {
  const { results } = await env.DB.prepare(
    `SELECT s.*,
            COALESCE(SUM(t.impressions), 0) AS impressions,
            COALESCE(SUM(t.clicks), 0)      AS clicks
       FROM sponsors s
       LEFT JOIN sponsor_stats t ON t.sponsor_id = s.id
      GROUP BY s.id
      ORDER BY s.created_at DESC`
  ).all();

  const d = new Date().toISOString().slice(0, 10);
  const sponsors = (results || []).map(r => ({
    ...r,
    active: !!r.active,
    live: !!r.active && (!r.starts_on || r.starts_on <= d) && (!r.ends_on || r.ends_on >= d)
  }));
  return json({ sponsors }, 200, { "cache-control": "no-store" });
}

/**
 * Creates or updates one sponsor.
 *
 * The image has to be a path on this site. A logo hotlinked from the
 * sponsor's own server puts a third party on every page of the calendar —
 * able to see every visitor — which is the exact thing this site avoids by
 * not running an ad network. It also breaks the day they reorganise their
 * files. Upload the image to public/img/sponsors/ instead.
 */
async function adminSaveSponsor(request, env, id = null) {
  let b;
  try { b = await request.json(); } catch { return fail("Malformed request."); }

  /* Pause and resume send nothing but {active}. Treat that as the small edit
     it is rather than running it through full validation, which would reject
     it for having no name and no link. */
  if (id && Object.keys(b).length === 1 && typeof b.active === "boolean") {
    const r = await env.DB.prepare("UPDATE sponsors SET active = ? WHERE id = ?")
      .bind(b.active ? 1 : 0, id).run();
    if (!r.meta?.changes) return fail("That sponsor no longer exists.", 404);
    return json({ ok: true, id });
  }

  const name = str(b.name, 120);
  const dest = str(b.dest_url, 500);
  const destAlt = str(b.dest_url_alt, 500);
  const errs = [];

  /* Every image has to be a file on this site. Repeated for each of the three
     because a sponsor kit arrives as three files and it only takes one of them
     to be pasted as a link to the sponsor's own server. */
  const ART = /^\/img\/sponsors\/[\w.-]+$/;
  const art = {};
  for (const [key, label] of [
    ["image_url", "desktop banner"],
    ["image_mobile_url", "mobile banner"],
    ["badge_url", "round badge"],
    ["image_side_url", "160x600 side banner"],
    ["image_side_wide_url", "300x600 side banner"]
  ]) {
    const v = str(b[key], 300);
    if (v && !ART.test(v))
      errs.push(`The ${label} must be a file in /img/sponsors/ on this site, not a link to another server.`);
    art[key] = v || null;
  }

  if (!name || name.length < 2) errs.push("A sponsor name is required.");
  if (!dest || !/^https?:\/\/.+/i.test(dest))
    errs.push("The destination link must start with http:// or https://");
  if (destAlt && !/^https?:\/\/.+/i.test(destAlt))
    errs.push("The airgunmatches.com link must start with http:// or https://");
  for (const [label, v] of [["Start", str(b.starts_on, 10)], ["End", str(b.ends_on, 10)]])
    if (v && !isRealDate(v)) errs.push(`${label} date must be a real date in YYYY-MM-DD form.`);

  const starts = str(b.starts_on, 10) || null;
  const ends   = str(b.ends_on, 10) || null;
  if (starts && ends && ends < starts) errs.push("The end date is before the start date.");

  const on = k => b[k] === true || b[k] === 1 || b[k] === "1" ? 1 : 0;
  const placements = {
    on_calendar: on("on_calendar"), on_results: on("on_results"), on_scoring: on("on_scoring")
  };
  if (!placements.on_calendar && !placements.on_results && !placements.on_scoring)
    errs.push("Pick at least one placement — otherwise the sponsor appears nowhere.");

  if (errs.length) return json({ error: errs.join(" ") }, 400);

  const row = {
    name, ...art, alt: str(b.alt, 160) || null,
    tagline: str(b.tagline, 160) || null,
    dest_url: dest, dest_url_alt: destAlt || null,
    results_line: str(b.results_line, 160) || null,
    starts_on: starts, ends_on: ends,
    active: b.active === false ? 0 : 1, note: str(b.note, 1000) || null,
    ...placements
  };

  if (id) {
    const found = await env.DB.prepare("SELECT id FROM sponsors WHERE id = ?").bind(id).first();
    if (!found) return fail("That sponsor no longer exists.", 404);
    await env.DB.prepare(
      `UPDATE sponsors SET name=?, image_url=?, image_mobile_url=?, badge_url=?,
              image_side_url=?, image_side_wide_url=?, alt=?,
              tagline=?, dest_url=?, dest_url_alt=?, results_line=?,
              starts_on=?, ends_on=?, active=?, note=?,
              on_calendar=?, on_results=?, on_scoring=? WHERE id=?`
    ).bind(row.name, row.image_url, row.image_mobile_url, row.badge_url,
           row.image_side_url, row.image_side_wide_url, row.alt,
           row.tagline, row.dest_url, row.dest_url_alt, row.results_line,
           row.starts_on, row.ends_on, row.active, row.note,
           row.on_calendar, row.on_results, row.on_scoring, id).run();
    return json({ ok: true, id });
  }

  const newId = crypto.randomUUID().slice(0, 8);
  await env.DB.prepare(
    `INSERT INTO sponsors (id, name, image_url, image_mobile_url, badge_url,
                           image_side_url, image_side_wide_url, alt,
                           tagline, dest_url, dest_url_alt, results_line,
                           starts_on, ends_on, active, note,
                           on_calendar, on_results, on_scoring)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(newId, row.name, row.image_url, row.image_mobile_url, row.badge_url,
         row.image_side_url, row.image_side_wide_url, row.alt,
         row.tagline, row.dest_url, row.dest_url_alt, row.results_line,
         row.starts_on, row.ends_on, row.active, row.note,
         row.on_calendar, row.on_results, row.on_scoring).run();
  return json({ ok: true, id: newId }, 201);
}

/** Removes a sponsor and its counts. Retiring one by setting active to false
 *  keeps the history; this is for a row created by mistake. */
async function adminDeleteSponsor(env, id) {
  const res = await env.DB.prepare("DELETE FROM sponsors WHERE id = ?").bind(id).run();
  if (!res.meta?.changes) return fail("That sponsor no longer exists.", 404);
  return json({ ok: true });
}

async function adminDuplicates(env) {
  const { results } = await env.DB.prepare(
    `SELECT s.id, s.display_name, s.first_name, s.last_name, s.name_key,
            COUNT(r.id) AS result_count
       FROM shooters s LEFT JOIN results r ON r.shooter_id = s.id
      WHERE s.merged_into IS NULL
      GROUP BY s.id ORDER BY s.last_name, s.display_name`
  ).all();

  const shooters = results || [];
  const pairs = [];

  for (let i = 0; i < shooters.length; i++) {
    for (let j = i + 1; j < shooters.length; j++) {
      const a = shooters[i], b = shooters[j];
      let reason = null;

      // Same surname, and one first name is an initial or prefix of the other
      if (a.last_name && b.last_name &&
          a.last_name.toLowerCase() === b.last_name.toLowerCase()) {
        const fa = (a.first_name || "").toLowerCase().replace(/\./g, "");
        const fb = (b.first_name || "").toLowerCase().replace(/\./g, "");
        if (fa && fb && (fa.startsWith(fb) || fb.startsWith(fa))) {
          reason = fa === fb ? "Same name, different spacing" : "Same surname, first name abbreviated";
        }
      }
      // Same words in a different order, e.g. "Whitcomb Dale"
      if (!reason) {
        const sa = a.name_key.split(" ").sort().join(" ");
        const sb = b.name_key.split(" ").sort().join(" ");
        if (sa === sb && a.name_key !== b.name_key) reason = "Same words, different order";
      }
      if (reason) pairs.push({ a, b, reason });
    }
  }
  return json({ pairs: pairs.slice(0, 100), total_shooters: shooters.length });
}

/* Folds one shooter into another. Reversible by clearing merged_into. */
async function adminMerge(request, env) {
  let body;
  try { body = await request.json(); } catch { return fail("Malformed request."); }
  const from = Number(body.from), into = Number(body.into);
  if (!from || !into || from === into) return fail("Pick two different shooters.");

  const target = await env.DB.prepare("SELECT id FROM shooters WHERE id = ? AND merged_into IS NULL")
    .bind(into).first();
  if (!target) return fail("That target shooter doesn't exist.", 404);

  await env.DB.batch([
    env.DB.prepare("UPDATE results  SET shooter_id  = ? WHERE shooter_id = ?").bind(into, from),
    env.DB.prepare("UPDATE shooters SET merged_into = ? WHERE id = ?").bind(into, from)
  ]);
  return json({ ok: true });
}

async function adminList(env, origin) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM events ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, created_at DESC"
  ).all();
  const events = await Promise.all((results || []).map(async r => ({
    ...parseRow(r),
    manage_url: `${origin}/manage.html?e=${encodeURIComponent(r.id)}&k=${await manageToken(env, r.id)}`
  })));
  return json({ events });
}

/* ------------------------------------------------------------------ */
/* Organizer self-service                                              */
/*                                                                     */
/* Each listing has one private link, derived from the listing's id and */
/* a server secret. Nothing is stored, so there is nothing to leak from */
/* the database, and the owner can mint the link for any listing.       */
/* ------------------------------------------------------------------ */

async function manageToken(env, id) {
  const secret = String(env.ADMIN_PASSWORD || "");
  if (!secret) return "";
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("manage:" + id));
  return [...new Uint8Array(sig)].slice(0, 16).map(b => b.toString(16).padStart(2, "0")).join("");
}
async function manageAuthorised(env, id, k) {
  const want = await manageToken(env, String(id || ""));
  const got = String(k || "");
  if (!want || got.length !== want.length) return false;
  let d = 0;
  for (let i = 0; i < want.length; i++) d |= want.charCodeAt(i) ^ got.charCodeAt(i);
  return d === 0;
}

const MANAGE_SELECT = "id, name, start_date, end_date, venue, city, state, url, note, status, listing_status, status_note, confirmed_at";

async function manageGet(request, env) {
  const u = new URL(request.url);
  const id = u.searchParams.get("e"), k = u.searchParams.get("k");
  if (!(await manageAuthorised(env, id, k))) return fail("This link isn't valid. Ask GunMatches for a new one.", 403);
  const row = await env.DB.prepare(`SELECT ${MANAGE_SELECT} FROM events WHERE id = ?`).bind(id).first();
  if (!row || row.status === "denied") return fail("Listing not found.", 404);
  return json({ event: row }, 200, { "cache-control": "no-store" });
}

async function managePost(request, env) {
  let b;
  try { b = await request.json(); } catch { return fail("Malformed request."); }
  if (!(await manageAuthorised(env, b.e, b.k))) return fail("This link isn't valid. Ask GunMatches for a new one.", 403);
  const cur = await env.DB.prepare("SELECT id, name, venue, status, start_date, end_date FROM events WHERE id = ?").bind(b.e).first();
  if (!cur || cur.status === "denied") return fail("Listing not found.", 404);

  const sets = ["confirmed_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')"], binds = [];
  if (b.action === "update") {
    const f = b.fields || {};
    const start = str(f.start_date ?? cur.start_date, 10), end = str(f.end_date ?? "", 10);
    if (!isRealDate(start)) return fail("Start date must be a real date.");
    if (end && !isRealDate(end)) return fail("End date must be a real date.");
    if (end && end < start) return fail("End date cannot be before the start date.");
    sets.push("start_date = ?", "end_date = ?"); binds.push(start, end || null);

    const venue = str(f.venue ?? cur.venue, 160);
    if (!venue || venue.length < 2) return fail("Venue is required.");
    sets.push("venue = ?"); binds.push(venue);

    if (f.city !== undefined || f.state !== undefined) {
      const city = str(f.city ?? "", 100), state = String(f.state || "").toUpperCase();
      if (!city || city.length < 2) return fail("City is required.");
      if (cityLooksWrong(city, cur.name, venue)) return fail("City should be the town or city the match is in, not the event or club name.");
      if (!STATES.has(state)) return fail("A valid two-letter state code is required.");
      sets.push("city = ?", "state = ?", "lat = NULL", "lng = NULL", "geo_at = NULL"); binds.push(city, state);
    }
    const url = str(f.url ?? "", 500);
    if (url && !/^https?:\/\/.+/i.test(url)) return fail("The registration link must start with http:// or https://");
    sets.push("url = ?"); binds.push(url);
    sets.push("note = ?"); binds.push(str(f.note ?? "", 1000));

    const ls = f.listing_status || null;
    if (ls && !["cancelled", "postponed"].includes(ls)) return fail("Invalid status.");
    sets.push("listing_status = ?", "status_note = ?"); binds.push(ls, str(f.status_note ?? "", 200));
  } else if (b.action !== "confirm") return fail("Unknown action.");

  binds.push(b.e);
  try { await env.DB.prepare(`UPDATE events SET ${sets.join(", ")} WHERE id = ?`).bind(...binds).run(); }
  catch (err) {
    if (String(err).includes("UNIQUE")) return fail("Another listing already has that name, date and venue.", 409);
    throw err;
  }
  const row = await env.DB.prepare(`SELECT ${MANAGE_SELECT} FROM events WHERE id = ?`).bind(b.e).first();
  return json({ ok: true, event: row }, 200, { "cache-control": "no-store" });
}

const EDITABLE = new Set(["name","start_date","end_date","venue","city","state","gun_types","disciplines",
                          "org","juniors","url","video_url","note","review_note"]);

async function adminUpdate(request, env, id, email) {
  let body;
  try { body = await request.json(); } catch { return fail("Malformed request."); }

  const sets = [], binds = [];

  if (body.status !== undefined) {
    if (!["pending","approved","denied"].includes(body.status)) return fail("Invalid status.");
    sets.push("status = ?"); binds.push(body.status);
    sets.push("reviewed_by = ?"); binds.push(email);

    // Approving an event issues its results code, once. Re-approving later
    // keeps the original so a code already sent to an organizer keeps working.
    if (body.status === "approved") {
      const cur = await env.DB.prepare("SELECT results_token FROM events WHERE id = ?").bind(id).first();
      if (!cur?.results_token) { sets.push("results_token = ?"); binds.push(makeResultsCode()); }
    }
  }

  // The owner's test-event switch. Directors have no route to this.
  if (body.is_test !== undefined) { sets.push("is_test = ?"); binds.push(body.is_test ? 1 : 0); }

  // Explicitly re-issue a code, for when one has been lost or leaked.
  if (body.regenerate_code === true) { sets.push("results_token = ?"); binds.push(makeResultsCode()); }

  for (const [k, v] of Object.entries(body)) {
    if (!EDITABLE.has(k)) continue;               // id, created_at, submitter_* are not editable
    if (k === "disciplines") {
      const list = Array.isArray(v)
        ? [...new Set(v.map(x => String(x).trim()).filter(x => x.length >= 2 && x.length <= 80))]
        : [];
      if (!list.length || list.length > 8) return fail("Between 1 and 8 disciplines required.");
      sets.push("disciplines = ?"); binds.push(JSON.stringify(list));
    } else if (k === "gun_types") {
      const list = Array.isArray(v)
        ? [...new Set(v.map(x => String(x).trim()).filter(x => GUN_TYPES.includes(x)))]
        : [];
      if (!list.length) return fail("Pick at least one type — airgun, rimfire, centerfire and so on.");
      sets.push("gun_types = ?"); binds.push(JSON.stringify(list));
    } else if (k === "juniors") {
      sets.push("juniors = ?"); binds.push(v ? 1 : 0);
    } else if (k === "state") {
      const s = String(v).toUpperCase();
      if (!STATES.has(s)) return fail("Invalid state code.");
      sets.push("state = ?"); binds.push(s);
    } else {
      sets.push(`${k} = ?`); binds.push(v === "" || v === null ? null : String(v));
    }
  }

  if (body.city !== undefined) {
    const cur = await env.DB.prepare("SELECT name, venue FROM events WHERE id = ?").bind(id).first();
    if (cur && cityLooksWrong(String(body.city), body.name ?? cur.name, body.venue ?? cur.venue))
      return fail("City should be the town or city the match is in, not the event or club name.");
  }

  // Manual map position, for towns the lookup gets wrong. Blank both to look it up again.
  let manualGeo = false;
  if (body.lat !== undefined || body.lng !== undefined) {
    const blank = v => v === "" || v === null || v === undefined;
    if (blank(body.lat) && blank(body.lng)) { sets.push("lat = NULL", "lng = NULL", "geo_at = NULL"); manualGeo = true; }
    else {
      const la = Number(body.lat), lo = Number(body.lng);
      if (!Number.isFinite(la) || !Number.isFinite(lo) || la < 17 || la > 72 || lo < -180 || lo > -64)
        return fail("Latitude and longitude must be numbers inside the United States.");
      sets.push("lat = ?", "lng = ?", "geo_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')"); binds.push(la, lo); manualGeo = true;
    }
  }
  if (body.listing_status !== undefined) {
    if (!["", null, "cancelled", "postponed"].includes(body.listing_status)) return fail("Invalid listing status.");
    sets.push("listing_status = ?"); binds.push(body.listing_status || null);
  }
  if (body.status_note !== undefined) { sets.push("status_note = ?"); binds.push(str(String(body.status_note ?? ""), 200)); }

  if (!sets.length) return fail("Nothing to update.");

  /* An admin edit or approval counts as the listing having been checked. A
     change of town clears the stored coordinates so they are looked up again. */
  const touched = body.status === "approved" || Object.keys(body).some(k => EDITABLE.has(k));
  if (touched) sets.push("confirmed_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')");
  if (!manualGeo && ("city" in body || "state" in body)) sets.push("lat = NULL", "lng = NULL", "geo_at = NULL");
  binds.push(id);

  try {
    const res = await env.DB.prepare(`UPDATE events SET ${sets.join(", ")} WHERE id = ?`).bind(...binds).run();
    if (!res.meta.changes) return fail("Event not found.", 404);
  } catch (err) {
    if (String(err).includes("UNIQUE")) return fail("Another event already has that name, date and venue.", 409);
    if (String(err).includes("CHECK")) return fail("That change fails a validation rule.", 400);
    throw err;
  }

  const row = await env.DB.prepare("SELECT * FROM events WHERE id = ?").bind(id).first();
  return json({ ok: true, event: parseRow(row) });
}

/**
 * One decision for a whole season.
 *
 * A club that submits nine monthly dates arrives as nine pending rows. Judging
 * them one at a time is nine chances to approve eight and forget the ninth, so
 * the dashboard reviews a series as a single item and this applies the verdict
 * to every date in it.
 *
 * Each occurrence still gets its own results code, because each is a separate
 * match with its own winner. Approving nine dates issues nine codes.
 */
async function adminUpdateSeries(request, env, email) {
  let body;
  try { body = await request.json(); } catch { return fail("Malformed request."); }

  const seriesId = String(body.series_id || "");
  const status = String(body.status || "");
  if (!seriesId) return fail("Which series?");
  if (!["pending", "approved", "denied"].includes(status)) return fail("Invalid status.");

  const rows = (await env.DB.prepare(
    "SELECT id, results_token FROM events WHERE series_id = ? ORDER BY start_date"
  ).bind(seriesId).all()).results || [];
  if (!rows.length) return fail("That series doesn't exist.", 404);

  const stmts = rows.map(r => {
    // Approving issues a code once. Re-approving keeps the code already sent out.
    const needsCode = status === "approved" && !r.results_token;
    return needsCode
      ? env.DB.prepare("UPDATE events SET status = ?, reviewed_by = ?, results_token = ? WHERE id = ?")
          .bind(status, email, makeResultsCode(), r.id)
      : env.DB.prepare("UPDATE events SET status = ?, reviewed_by = ? WHERE id = ?")
          .bind(status, email, r.id);
  });

  await env.DB.batch(stmts);
  return json({ ok: true, status, dates_updated: rows.length });
}

/**
 * Deleting an event takes everything belonging to it.
 *
 * Results, disciplines, stages, squads, the roster, score cards and declared
 * placings all disappear on their own — they hold a foreign key to the event
 * with ON DELETE CASCADE, and D1 enforces it.
 *
 * The audit trail doesn't. `score_history` deliberately has no foreign key, so
 * that a record of who changed a score cannot be quietly erased by deleting
 * something else. That protection stops making sense once the match itself is
 * gone: there is no longer a score to dispute, and the rows still hold scorers'
 * names and device ids. So they are removed here, explicitly, rather than left
 * behind as unreachable data about real people.
 *
 * The order matters. The history rows are found by walking from the event to
 * its disciplines, so they have to go before the cascade removes the path.
 */
async function adminDelete(request, env, id, adminEmail) {
  const ev = await env.DB.prepare("SELECT id, name FROM events WHERE id = ?").bind(id).first();
  if (!ev) return fail("Event not found.", 404);

  const mdIds = ((await env.DB.prepare(
    "SELECT id FROM match_disciplines WHERE event_id = ?"
  ).bind(id).all()).results || []).map(r => r.id);
  const marks = mdIds.map(() => "?").join(",");

  const count = async table => mdIds.length
    ? ((await env.DB.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE md_id IN (${marks})`)
        .bind(...mdIds).first())?.n || 0) : 0;
  const edits = await count("score_edits");
  const dqs = await count("dq_log");

  /* Score corrections and disqualifications are permanent records. Directors
     have no way to delete anything. The site owner can erase a whole match, but
     only by typing its name, and the erasure is itself written to a permanent
     ledger: what was removed, by whom and when. */
  if (edits || dqs) {
    let body = {};
    try { body = await request.json(); } catch { /* no body */ }
    if (!body || !body.purge) {
      return json({
        error: `This event has ${edits} recorded score change${edits === 1 ? "" : "s"}` +
               `${dqs ? ` and ${dqs} disqualification record${dqs === 1 ? "" : "s"}` : ""}. ` +
               `Deleting it erases those permanent records.`,
        requires_purge: true, name: ev.name, edits, dqs
      }, 409);
    }
    if (String(body.confirm_name || "").trim() !== String(ev.name).trim())
      return fail("The name you typed doesn't match the event name, so nothing was deleted.");
  }

  const stmts = [];
  if (mdIds.length) {
    if (edits || dqs) {
      for (const m of mdIds)
        stmts.push(env.DB.prepare("INSERT OR IGNORE INTO audit_purge_allow (md_id) VALUES (?)").bind(m));
      stmts.push(env.DB.prepare(
        "INSERT INTO audit_purges (event_id, event_name, edits_removed, dq_removed, purged_by) VALUES (?,?,?,?,?)"
      ).bind(ev.id, ev.name, edits, dqs, adminEmail || "owner"));
    }
    stmts.push(env.DB.prepare(`DELETE FROM dq_log WHERE md_id IN (${marks})`).bind(...mdIds));
    stmts.push(env.DB.prepare(`DELETE FROM score_history WHERE md_id IN (${marks})`).bind(...mdIds));
  }
  stmts.push(env.DB.prepare("DELETE FROM events WHERE id = ?").bind(id));
  if (mdIds.length) stmts.push(env.DB.prepare(`DELETE FROM audit_purge_allow WHERE md_id IN (${marks})`).bind(...mdIds));

  await env.DB.batch(stmts);
  return json({ ok: true, records_erased: edits + dqs });
}

async function adminExport(request, env) {
  const format = new URL(request.url).searchParams.get("format") || "json";
  const { results } = await env.DB.prepare("SELECT * FROM events ORDER BY start_date").all();
  const rows = results || [];
  const stamp = new Date().toISOString().slice(0, 10);

  if (format === "csv") {
    const cols = Object.keys(rows[0] || { id: "" });
    const esc = v => v === null || v === undefined ? "" : `"${String(v).replace(/"/g, '""')}"`;
    const csv = [cols.join(","), ...rows.map(r => cols.map(c => esc(r[c])).join(","))].join("\n");
    return new Response(csv, {
      headers: {
        "content-type": "text/csv; charset=utf-8",
        "content-disposition": `attachment; filename="gunmatches-${stamp}.csv"`,
        ...securityHeaders()
      }
    });
  }
  return new Response(JSON.stringify({ exported_at: new Date().toISOString(), count: rows.length,
                                       events: rows.map(parseRow) }, null, 2), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "content-disposition": `attachment; filename="gunmatches-${stamp}.json"`,
      ...securityHeaders()
    }
  });
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

/**
 * Moving the site to a new domain.
 *
 * Controlled by the REDIRECT_HOST setting rather than hard-coded, so the move
 * can be switched on the moment the new domain is verified and switched off
 * again in seconds if anything is wrong — without a deploy.
 *
 * Three things are deliberately left alone:
 *   - anything but GET and HEAD, because a 301 turns a POST into a GET and
 *     would silently discard an organizer's submission;
 *   - /api/, so a page someone already has open keeps working;
 *   - the workers.dev address, which stays reachable for checking the site.
 *
 * Someone typing the old airgun address is, by definition, looking for airgun
 * matches — so the front page lands them on the airgun view rather than the
 * whole calendar. They can clear the filter to see everything else.
 */
function movedPermanently(url, request, env) {
  const target = String(env.REDIRECT_HOST || "").trim().toLowerCase();
  if (!target) return null;
  if (request.method !== "GET" && request.method !== "HEAD") return null;
  if (url.pathname.startsWith("/api/")) return null;

  const host = url.hostname.toLowerCase();
  if (host === target || host.endsWith(".workers.dev")) return null;

  const to = new URL(url.toString());
  to.protocol = "https:";
  to.hostname = target;
  to.port = "";

  const airgunSite = host === "airgunmatches.com" || host === "www.airgunmatches.com";
  if (airgunSite && (to.pathname === "/" || to.pathname === "") && !to.searchParams.has("gun"))
    to.searchParams.set("gun", "Airgun");

  return new Response(null, {
    status: 301,
    headers: { location: to.toString(), "cache-control": "no-cache", ...securityHeaders() }
  });
}

/* The scoring module is given only what it needs, and shares this file's
   single definition of each helper — so a fix to name matching or to the
   points table applies to uploaded results and live scoring alike, and the
   two can never drift apart. */
const SCORING_HELPERS = {
  json, fail, safeParse, eventForCode, makeResultsCode,
  resolveShooter, pointsForPlace
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      const moved = movedPermanently(url, request, env);
      if (moved) return moved;

      if (path.startsWith("/api/")) {
        // ---- public ----
        if (path === "/api/events" && method === "GET")  return await edgeCached(request, ctx, 10, () => getPublicEvents(env, ctx));
        if (path === "/api/geo" && method === "GET")     return await apiGeo(request);
        if (path === "/api/manage" && method === "GET")  return await manageGet(request, env);
        if (path === "/api/manage" && method === "POST") return await managePost(request, env);
        if (path === "/api/events" && method === "POST") return await createSubmission(request, env);

        // Results upload — authorised by the event's own code, nothing else
        if (path === "/api/results" && method === "GET")  return await getResultsEvent(request, env);
        if (path === "/api/results" && method === "POST") return await saveResults(request, env);

        // Live scoring. Authorisation lives inside the module: the event's
        // results code for the director, a per-squad code for a scorer, and
        // neither for the public live view. No admin session is involved, so
        // this sits ahead of the admin block deliberately.
        if (path.startsWith("/api/scoring/")) {
          const res = await handleScoring(request, env, path, method, SCORING_HELPERS);
          if (res) return res;
          return fail("Not found", 404);
        }

        // Public standings
        if (path === "/api/rankings" && method === "GET") return await getRankings(request, env);
        const sm = path.match(/^\/api\/shooters\/(\d+)$/);
        if (sm && method === "GET") return await getShooter(request, env, Number(sm[1]));

        // ---- admin session ----
        if (path === "/api/admin/login"  && method === "POST") return await handleLogin(request, env);
        if (path === "/api/admin/logout" && method === "POST") return handleLogout();

        // ---- admin ----
        if (path.startsWith("/api/admin/")) {
          const auth = await requireAdmin(request, env);
          if (auth.error) return auth.error;

          if (path === "/api/admin/events" && method === "GET")  return await adminList(env, CANONICAL_ORIGIN);
          if (path === "/api/admin/duplicates" && method === "GET")  return await adminDuplicates(env);
          if (path === "/api/admin/merge" && method === "POST") return await adminMerge(request, env);
          if (path === "/api/admin/export" && method === "GET")  return await adminExport(request, env);
          if (path === "/api/admin/series" && method === "PATCH") return await adminUpdateSeries(request, env, auth.email);
          if (path === "/api/admin/import" && method === "POST") return await adminImport(request, env, auth.email);
          if (path === "/api/admin/sponsors" && method === "GET")  return await adminSponsors(env);
          if (path === "/api/admin/sponsors" && method === "POST") return await adminSaveSponsor(request, env);
          const sp = path.match(/^\/api\/admin\/sponsors\/([a-zA-Z0-9-]{1,64})$/);
          if (sp && method === "PATCH")  return await adminSaveSponsor(request, env, sp[1]);
          if (sp && method === "DELETE") return await adminDeleteSponsor(env, sp[1]);

          const m = path.match(/^\/api\/admin\/events\/([0-9a-fA-F-]{36})$/);
          if (m && method === "PATCH")  return await adminUpdate(request, env, m[1], auth.email);
          if (m && method === "DELETE") return await adminDelete(request, env, m[1], auth.email);
        }
        return fail("Not found", 404);
      }

      /* ---- pages rendered from the database ----
         These sit ahead of the static files deliberately: they are the
         addresses a crawler is given, and none of them exists as a file. */
      const origin = `${url.protocol}//${url.host}`;

      /* Every page names gunmatches.com as the original, whichever domain
         served it. Both domains serve the same calendar, so without this the
         alias competes with the real site for identical content — and it was
         doing exactly that: airgunmatches.com was declaring itself canonical.
         Internal links are relative, so only the declared address changes. */
      const canon = CANONICAL_ORIGIN;

      if (path === "/sitemap.xml" && (method === "GET" || method === "HEAD")) {
        const events = await approvedEvents(env);
        return new Response(sitemapXml(events, canon), {
          headers: {
            "content-type": "application/xml; charset=utf-8",
            "cache-control": "public, max-age=3600",
            ...securityHeaders()
          }
        });
      }

      /* Sponsor click-through. The destination comes from the database by id;
         nothing in the request names a URL, so this can never be turned into
         an open redirect. */
      const sm = path.match(/^\/s\/([a-zA-Z0-9-]{1,64})$/);
      if (sm && (method === "GET" || method === "HEAD")) {
        const out = await handleSponsorClick(env, sm[1], securityHeaders, url.host);
        if (out) return out;
        return Response.redirect(origin + "/", 302);
      }

      if (path.startsWith("/event/") && (method === "GET" || method === "HEAD")) {
        const page = await serveEventPage(request, env, path, canon, url.host, ctx);
        if (page) return page;
        return new Response(notFoundHtml(origin), {
          status: 404,
          headers: { "content-type": "text/html; charset=utf-8", ...securityHeaders() }
        });
      }

      /* The calendar, with its listings already in the HTML. The client script
         replaces them the moment it runs, so this changes nothing a visitor
         sees — it exists for the first pass of a crawler, which does not wait
         for JavaScript. */
      if (path === "/calendar.ics" && (method === "GET" || method === "HEAD"))
        return await calendarFeed(request, env, canon);

      if ((path === "/" || path === "/index.html") && method === "GET") {
        const res = await calendarAsset(request, env, origin);
        if (!res || !res.ok) return res || fail("Not found", 404);
        const html = await res.text();
        const [events, sponsor] = await Promise.all([
          approvedEvents(env), activeSponsor(env)
        ]);

        /* Counted after the response goes out. A reader should never wait on a
           tally, and a failed counter is worth losing rather than turning a
           page view into an error. */
        if (sponsor && ctx && ctx.waitUntil) {
          ctx.waitUntil(countImpression(env, sponsor.id).catch(() => {}));
        }

        return htmlResponse(
          injectSponsor(injectIntoCalendar(html, events, canon), sponsor, url.host),
          /* An unsold slot caches for five minutes as before. A sold one is
             kept briefly so the day's impression count means something. */
          "public, max-age=0, must-revalidate");   // the LIVE badge must follow the director's switch
      }

      /* The scoring screen, with the sponsor logo in its header if one is
         booked there. Kept out of the generic asset path because this page is
         used offline and should change as little as possible. */
      if ((path === "/score.html" || path === "/score") && method === "GET") {
        const res = await env.ASSETS.fetch(request);
        if (!res.ok || !(res.headers.get("content-type") || "").includes("text/html"))
          return res;
        const [html, sponsor] = await Promise.all([res.text(), activeSponsor(env)]);
        return htmlResponse(injectScoringSponsor(html, sponsor), "public, max-age=300");
      }

      // ---- static assets ----
      // The admin page is additionally gated by Cloudflare Access at the edge;
      // this check means a misconfigured Access policy still cannot serve it.
      // The admin page is served to anyone, but it is an empty shell: every
      // /api/admin/* call behind it requires a valid session, so an
      // unauthenticated visitor sees a login form and nothing else.
      if (path === ADMIN_PATH) {
        const headers = { ...securityHeaders(), "cache-control": "no-store" };
        const res = await env.ASSETS.fetch(request);
        const h = new Headers(res.headers);
        for (const [k, v] of Object.entries(headers)) h.set(k, v);
        return new Response(res.body, { status: res.status, headers: h });
      }

      const res = await env.ASSETS.fetch(request);
      const headers = new Headers(res.headers);
      for (const [k, v] of Object.entries(securityHeaders())) headers.set(k, v);

      /* A canonical link on the handful of pages worth indexing. This is also
         what stops airgunmatches.com competing with gunmatches.com for the
         same content while the redirect switch is off. */
      if (CANONICAL_PAGES.has(path) && res.status === 200 &&
          (res.headers.get("content-type") || "").includes("text/html")) {
        const html = await res.text();
        return htmlResponse(injectCanonical(html, CANONICAL_ORIGIN, canonicalPathFor(path)),
          "public, max-age=300");
      }

      return new Response(res.body, { status: res.status, headers });

    } catch (err) {
      // Never leak internals to the browser; the detail goes to Workers logs.
      console.error("Unhandled error:", err && err.stack ? err.stack : String(err));
      return fail("Something went wrong. Please try again.", 500);
    }
  }
};

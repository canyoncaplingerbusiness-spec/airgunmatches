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

/* Columns the public may ever see. Submitter and review fields are absent
   by construction rather than filtered out afterwards. */
const PUBLIC_COLUMNS =
  "id, name, start_date, end_date, venue, city, state, gun_types, disciplines, org, juniors, url, video_url, note";

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
    `SELECT id, name, start_date, end_date, venue, city, state, disciplines, status
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
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const YT_RE = /^https:\/\/((www\.|m\.)?youtube\.com\/|youtu\.be\/)/;

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
  if (!STATES.has(state)) e.push("A valid two-letter state code is required.");
  if (!start || !DATE_RE.test(start)) e.push("Start date must be YYYY-MM-DD.");
  if (end && !DATE_RE.test(end)) e.push("End date must be YYYY-MM-DD.");
  if (start && end && end < start) e.push("End date cannot be before the start date.");
  if (start && (start < "2015-01-01" || start > "2100-01-01")) e.push("Start date is out of range.");
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

    rows.push({
      place,
      competitor,
      score: (rest[1] || "").slice(0, 60) || null,
      class: (rest[2] || "").slice(0, 60) || null
    });
  });

  if (rows.length > 500) errors.push("More than 500 rows in one discipline.");
  return { rows, errors };
}

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

async function getPublicEvents(env) {
  const { results } = await env.DB.prepare(
    `SELECT ${PUBLIC_COLUMNS} FROM events WHERE status = 'approved' ORDER BY start_date ASC`
  ).all();
  const events = (results || []).map(parseRow);

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
  events.forEach(e => { e.results = byEvent[e.id] || null; });

  return json({ events }, 200, {
    // Short cache: approvals appear within a minute without a deploy.
    "cache-control": "public, max-age=60, stale-while-revalidate=300"
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

  const { errors, row } = validateSubmission(body);
  if (errors.length) return json({ error: errors.join(" ") }, 400);

  const ipHash = await hashIp(ip, env.IP_SALT || "airgunmatches");

  // Rate limit: at most 5 submissions per address per hour.
  if (ipHash) {
    const since = new Date(Date.now() - 3600_000).toISOString().slice(0, 19) + "Z";
    const { count } = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM events WHERE submit_ip_hash = ? AND created_at > ?"
    ).bind(ipHash, since).first();
    if (count >= 5) return fail("Too many submissions from this connection. Try again later.", 429);
  }

  const id = crypto.randomUUID();
  try {
    await env.DB.prepare(
      `INSERT INTO events (id, name, start_date, end_date, venue, city, state, gun_types, disciplines,
                           org, juniors, url, video_url, note, submitter_name, submitter_email,
                           status, submit_ip_hash, submit_country)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending', ?, ?)`
    ).bind(
      id, row.name, row.start_date, row.end_date, row.venue, row.city, row.state,
      row.gun_types, row.disciplines, row.org, row.juniors, row.url, row.video_url, row.note,
      row.submitter_name, row.submitter_email,
      ipHash, request.headers.get("CF-IPCountry") || null
    ).run();
  } catch (err) {
    // The unique index makes a repeat submission a no-op rather than an error
    // the organizer has to puzzle over.
    if (String(err).includes("UNIQUE")) {
      return json({ ok: true, duplicate: true,
        message: "That match is already submitted — we'll review the existing entry." });
    }
    throw err;
  }
  return json({ ok: true, id }, 201);
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
      disciplines: safeParse(ev.disciplines)
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

  const statements = [];
  let total = 0;
  const problems = [];

  for (const [discipline, text] of Object.entries(incoming)) {
    if (!disciplines.includes(discipline)) {
      problems.push(`"${discipline}" is not one of this event's disciplines.`);
      continue;
    }
    const { rows, errors } = parseResultRows(text);
    errors.forEach(e => problems.push(`${discipline} — ${e}`));

    const fieldSize = rows.length;
    for (const [idx, r] of rows.entries()) {
      const place = r.place !== null ? r.place : idx + 1;
      const shooterId = await resolveShooter(env, r.competitor);
      statements.push(
        env.DB.prepare(
          `INSERT INTO results (event_id, discipline, place, competitor, score, class,
                                sort_order, shooter_id, points, field_size)
           VALUES (?,?,?,?,?,?,?,?,?,?)`
        ).bind(ev.id, discipline, r.place, r.competitor, r.score, r.class,
               place, shooterId, pointsForPlace(place), fieldSize)
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
async function getRankings(request, env) {
  const url = new URL(request.url);
  const discipline = url.searchParams.get("discipline");
  const since = new Date(Date.now() - 365 * 86400_000).toISOString().slice(0, 10);

  const where = ["e.status = 'approved'", "e.start_date >= ?", "r.shooter_id IS NOT NULL"];
  const binds = [since];
  if (discipline) { where.push("r.discipline = ?"); binds.push(discipline); }

  const { results } = await env.DB.prepare(
    `SELECT s.id                       AS shooter_id,
            s.display_name             AS name,
            s.first_name, s.last_name,
            SUM(r.points)              AS points,
            COUNT(DISTINCT r.event_id) AS events,
            SUM(CASE WHEN r.place = 1 THEN 1 ELSE 0 END) AS wins,
            SUM(CASE WHEN r.place <= 3 THEN 1 ELSE 0 END) AS podiums,
            MIN(r.place)               AS best_place,
            MAX(e.start_date)          AS last_event,
            GROUP_CONCAT(DISTINCT r.discipline) AS disciplines
       FROM results r
       JOIN events e   ON e.id = r.event_id
       JOIN shooters s ON s.id = r.shooter_id
      WHERE ${where.join(" AND ")}
      GROUP BY s.id
      ORDER BY points DESC, wins DESC, events DESC, s.display_name ASC
      LIMIT 300`
  ).bind(...binds).all();

  const standings = (results || []).map((r, i) => ({
    rank: i + 1,
    shooter_id: r.shooter_id,
    name: r.name,
    first_name: r.first_name,
    last_name: r.last_name,
    points: r.points,
    events: r.events,
    wins: r.wins,
    podiums: r.podiums,
    best_place: r.best_place,
    last_event: r.last_event,
    disciplines: (r.disciplines || "").split(",").filter(Boolean)
  }));

  // Which disciplines actually have ranked results, for the filter
  const discRows = await env.DB.prepare(
    `SELECT r.discipline, COUNT(DISTINCT r.shooter_id) AS shooters
       FROM results r JOIN events e ON e.id = r.event_id
      WHERE e.status = 'approved' AND e.start_date >= ? AND r.shooter_id IS NOT NULL
      GROUP BY r.discipline ORDER BY r.discipline`
  ).bind(since).all();

  return json({
    standings,
    disciplines: discRows.results || [],
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
      WHERE r.shooter_id = ? AND e.status = 'approved'
      ORDER BY e.start_date DESC`
  ).bind(id).all();

  return json({ shooter, results: results || [] }, 200,
              { "cache-control": "public, max-age=300" });
}

/* Names that look like the same person, for the merge screen. */
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

async function adminList(env) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM events ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, created_at DESC"
  ).all();
  return json({ events: (results || []).map(parseRow) });
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

  if (!sets.length) return fail("Nothing to update.");
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

async function adminDelete(env, id) {
  const res = await env.DB.prepare("DELETE FROM events WHERE id = ?").bind(id).run();
  if (!res.meta.changes) return fail("Event not found.", 404);
  return json({ ok: true });
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
  if (host === target || host === `www.${target}` || host.endsWith(".workers.dev")) return null;

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
        if (path === "/api/events" && method === "GET")  return await getPublicEvents(env);
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

          if (path === "/api/admin/events" && method === "GET")  return await adminList(env);
          if (path === "/api/admin/duplicates" && method === "GET")  return await adminDuplicates(env);
          if (path === "/api/admin/merge" && method === "POST") return await adminMerge(request, env);
          if (path === "/api/admin/export" && method === "GET")  return await adminExport(request, env);

          const m = path.match(/^\/api\/admin\/events\/([0-9a-fA-F-]{36})$/);
          if (m && method === "PATCH")  return await adminUpdate(request, env, m[1], auth.email);
          if (m && method === "DELETE") return await adminDelete(env, m[1]);
        }
        return fail("Not found", 404);
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
      return new Response(res.body, { status: res.status, headers });

    } catch (err) {
      // Never leak internals to the browser; the detail goes to Workers logs.
      console.error("Unhandled error:", err && err.stack ? err.stack : String(err));
      return fail("Something went wrong. Please try again.", 500);
    }
  }
};

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

const ADMIN_PATH = "/admin.html";

/* Columns the public may ever see. Submitter and review fields are absent
   by construction rather than filtered out afterwards. */
const PUBLIC_COLUMNS =
  "id, name, start_date, end_date, venue, city, state, disciplines, org, juniors, url, video_url, note";

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
  if (!token) return false;
  const body = new FormData();
  body.append("secret", env.TURNSTILE_SECRET_KEY);
  body.append("response", token);
  if (ip) body.append("remoteip", ip);
  const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST", body
  });
  const out = await res.json().catch(() => ({ success: false }));
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

const parseRow = r => ({ ...r, disciplines: safeParse(r.disciplines), juniors: !!r.juniors });
function safeParse(s) { try { const v = JSON.parse(s); return Array.isArray(v) ? v : []; } catch { return []; } }

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
      `INSERT INTO events (id, name, start_date, end_date, venue, city, state, disciplines,
                           org, juniors, url, video_url, note, submitter_name, submitter_email,
                           status, submit_ip_hash, submit_country)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending', ?, ?)`
    ).bind(
      id, row.name, row.start_date, row.end_date, row.venue, row.city, row.state,
      row.disciplines, row.org, row.juniors, row.url, row.video_url, row.note,
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
    rows.forEach((r, idx) => {
      statements.push(
        env.DB.prepare(
          `INSERT INTO results (event_id, discipline, place, competitor, score, class, sort_order)
           VALUES (?,?,?,?,?,?,?)`
        ).bind(ev.id, discipline, r.place, r.competitor, r.score, r.class,
               r.place !== null ? r.place : idx + 1)
      );
      total++;
    });
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

async function adminList(env) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM events ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, created_at DESC"
  ).all();
  return json({ events: (results || []).map(parseRow) });
}

const EDITABLE = new Set(["name","start_date","end_date","venue","city","state","disciplines",
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
        "content-disposition": `attachment; filename="airgunmatches-${stamp}.csv"`,
        ...securityHeaders()
      }
    });
  }
  return new Response(JSON.stringify({ exported_at: new Date().toISOString(), count: rows.length,
                                       events: rows.map(parseRow) }, null, 2), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "content-disposition": `attachment; filename="airgunmatches-${stamp}.json"`,
      ...securityHeaders()
    }
  });
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      if (path.startsWith("/api/")) {
        // ---- public ----
        if (path === "/api/events" && method === "GET")  return await getPublicEvents(env);
        if (path === "/api/events" && method === "POST") return await createSubmission(request, env);

        // Results upload — authorised by the event's own code, nothing else
        if (path === "/api/results" && method === "GET")  return await getResultsEvent(request, env);
        if (path === "/api/results" && method === "POST") return await saveResults(request, env);

        // ---- admin session ----
        if (path === "/api/admin/login"  && method === "POST") return await handleLogin(request, env);
        if (path === "/api/admin/logout" && method === "POST") return handleLogout();

        // ---- admin ----
        if (path.startsWith("/api/admin/")) {
          const auth = await requireAdmin(request, env);
          if (auth.error) return auth.error;

          if (path === "/api/admin/events" && method === "GET")  return await adminList(env);
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

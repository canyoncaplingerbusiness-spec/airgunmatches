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
/* Cloudflare Access verification                                      */
/* ------------------------------------------------------------------ */

let keyCache = { keys: null, at: 0 };

async function accessPublicKeys(teamDomain) {
  const fresh = Date.now() - keyCache.at < 60 * 60 * 1000;
  if (keyCache.keys && fresh) return keyCache.keys;
  const res = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`);
  if (!res.ok) throw new Error("could not fetch Access certificates");
  const { keys } = await res.json();
  keyCache = { keys, at: Date.now() };
  return keys;
}

const b64url = s => {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, c => c.charCodeAt(0));
};

/**
 * Verifies the Cf-Access-Jwt-Assertion header: real signature from our own
 * Access team, correct audience, not expired. Returns the reviewer's email
 * or null. Defence in depth — Access already gates the route, but a
 * misconfigured rule should not hand out admin rights.
 */
async function verifyAccess(request, env) {
  const token =
    request.headers.get("Cf-Access-Jwt-Assertion") ||
    (request.headers.get("cookie") || "").match(/CF_Authorization=([^;]+)/)?.[1];
  if (!token) return null;

  const [h, p, s] = token.split(".");
  if (!h || !p || !s) return null;

  let header, payload;
  try {
    header = JSON.parse(new TextDecoder().decode(b64url(h)));
    payload = JSON.parse(new TextDecoder().decode(b64url(p)));
  } catch { return null; }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) return null;
  if (payload.nbf && payload.nbf > now) return null;
  if (env.ACCESS_AUD && payload.aud) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(env.ACCESS_AUD)) return null;
  }

  const keys = await accessPublicKeys(env.ACCESS_TEAM_DOMAIN);
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) return null;

  const key = await crypto.subtle.importKey(
    "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
  );
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key, b64url(s), new TextEncoder().encode(`${h}.${p}`)
  );
  return ok ? (payload.email || "unknown") : null;
}

async function requireAdmin(request, env) {
  const email = await verifyAccess(request, env);
  if (!email) return { error: fail("Not authorised", 403) };
  return { email };
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
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

async function getPublicEvents(env) {
  const { results } = await env.DB.prepare(
    `SELECT ${PUBLIC_COLUMNS} FROM events WHERE status = 'approved' ORDER BY start_date ASC`
  ).all();
  return json({ events: (results || []).map(parseRow) }, 200, {
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
  }

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
      if (path === ADMIN_PATH) {
        const auth = await requireAdmin(request, env);
        if (auth.error) {
          return new Response("Not authorised.", { status: 403, headers: securityHeaders() });
        }
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

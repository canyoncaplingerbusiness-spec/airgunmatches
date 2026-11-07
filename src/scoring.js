/**
 * AirgunMatches.com — live match scoring
 *
 * Three separate keys reach this module, and they are never interchangeable:
 *
 *   event results code  → the match director. Sets up disciplines, stages,
 *                         squads and roster; opens and closes the match;
 *                         declares winners; publishes final standings.
 *   squad code          → one scorer, one squad, one discipline. Nothing else.
 *   no key at all       → public live standings, but only for a discipline the
 *                         director has explicitly opened to the public.
 *
 * Director codes resolve against events.results_token; squad codes resolve
 * against squads.code. They are looked up in different tables, so a squad code
 * can never satisfy a director route no matter how the request is shaped.
 *
 * THE SCOPE RULE
 * Every squad-authenticated write re-derives md_id and squad_id from the code
 * on the server. Values sent by the client are read for stage_id and
 * entrant_id only, and both are then checked to belong to that squad. A
 * hand-edited request cannot reach another squad's scores.
 */

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

const MODES = new Set(["stages", "direct"]);
const STATES = new Set(["setup", "live", "complete"]);
const SCORE_TYPES = new Set(["points", "group", "time"]);
const AGGREGATIONS = new Set(["sum", "best", "average", "bestn"]);

const MAX_STAGES = 40;
const MAX_SHOTS = 100;
const MAX_SQUADS = 60;
const MAX_ENTRANTS = 800;
const MAX_SYNC_ITEMS = 200;

/* A scorer tapping steadily produces a handful of writes a minute. This ceiling
   is far above real use and still stops a shared code being hammered. */
const RATE_LIMIT = 600;
const RATE_WINDOW_MS = 5 * 60_000;

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

const clean = (v, max = 120) => {
  const s = String(v ?? "").trim().replace(/\s+/g, " ");
  return s ? s.slice(0, max) : null;
};

/* Absent is not zero. Number(null) and Number("") are both 0, so an optional
   field left empty used to arrive as a real 0 — "shots fired: none" became
   "shots fired: 0", and a cleared perfect score became a ceiling of zero. Every
   caller guards with ?? or rejects falsy values, so returning null is safe and
   says what is actually true. */
const asInt = v => {
  if (v === null || v === undefined || String(v).trim() === "") return null;
  const n = Number(v);
  return Number.isInteger(n) ? n : null;
};

async function sha256(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

/** Writes per code, in a rolling window. Read-only routes are not counted. */
async function rateOk(env, code) {
  const bucket = Math.floor(Date.now() / RATE_WINDOW_MS);
  const key = await sha256(code);
  await env.DB.prepare(
    `INSERT INTO scoring_rate (code_hash, window_at, hits) VALUES (?,?,1)
     ON CONFLICT(code_hash, window_at) DO UPDATE SET hits = hits + 1`
  ).bind(key, bucket).run();
  const row = await env.DB.prepare(
    "SELECT hits FROM scoring_rate WHERE code_hash = ? AND window_at = ?"
  ).bind(key, bucket).first();
  return (row?.hits ?? 0) <= RATE_LIMIT;
}

/* ------------------------------------------------------------------ */
/* Authorisation                                                       */
/* ------------------------------------------------------------------ */

/** Director: the event's own results code. The match must be an approved event. */
async function asDirector(env, code, H) {
  const ev = await H.eventForCode(env, code);
  if (!ev || ev.status !== "approved") return null;
  return ev;
}

/** Scorer: a squad code. Resolves the whole chain in one query so the
 *  discipline, mode and event travel with it and nothing has to be trusted
 *  from the request body. */
async function asSquad(env, code) {
  const c = String(code || "").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12);
  if (c.length !== 12) return null;
  return await env.DB.prepare(
    `SELECT s.id AS squad_id, s.name AS squad_name, s.ordinal AS squad_ordinal,
            s.scorer_name, s.start_stage,
            d.id AS md_id, d.discipline, d.mode, d.state, d.relays,
            d.score_type, d.decimals, d.max_score, d.winner,
            e.id AS event_id, e.name AS event_name, e.start_date, e.venue,
            e.city, e.state AS event_state, e.status
       FROM squads s
       JOIN match_disciplines d ON d.id = s.md_id
       JOIN events e            ON e.id = d.event_id
      WHERE replace(upper(s.code), '-', '') = ?`
  ).bind(c).first();
}

/* ------------------------------------------------------------------ */
/* Stage rotation                                                      */
/* ------------------------------------------------------------------ */

/**
 * Give every squad that has no starting stage one, at random, spreading the
 * squads across the stages so no two start together until every stage has a
 * squad. Squads that already have a start are never changed, so reopening a
 * match or adding a late squad doesn't disturb anyone mid-match.
 */
async function assignStartStages(env, mdId) {
  const stages = (await env.DB.prepare(
    "SELECT ordinal FROM stages WHERE md_id = ? ORDER BY ordinal"
  ).bind(mdId).all()).results || [];
  if (!stages.length) return;
  const squads = (await env.DB.prepare(
    "SELECT id, start_stage FROM squads WHERE md_id = ? ORDER BY ordinal"
  ).bind(mdId).all()).results || [];

  const valid = new Set(stages.map(s => s.ordinal));
  const used = new Map(stages.map(s => [s.ordinal, 0]));
  for (const s of squads) if (valid.has(s.start_stage)) used.set(s.start_stage, used.get(s.start_stage) + 1);

  const stmts = [];
  for (const s of squads) {
    if (valid.has(s.start_stage)) continue;
    const low = Math.min(...used.values());
    const pool = [...used].filter(([, n]) => n === low).map(([o]) => o);
    const pick = pool[crypto.getRandomValues(new Uint32Array(1))[0] % pool.length];
    used.set(pick, used.get(pick) + 1);
    s.start_stage = pick;
    stmts.push(env.DB.prepare("UPDATE squads SET start_stage = ? WHERE id = ?").bind(pick, s.id));
  }
  if (stmts.length) await env.DB.batch(stmts);
}

/**
 * The order one squad shoots the stages in, and which of them it may score.
 *
 * It starts at its own stage, runs upward, and wraps round to stage 1. A stage
 * opens only when every competitor in the squad has a finished card on the one
 * before it. A stage that already has scores stays open regardless, so moving a
 * squad's start mid-match can't lock it out of work it has done.
 */
async function stagePlan(env, mdId, squadId, startStage) {
  const stages = (await env.DB.prepare(
    "SELECT id, ordinal, name, shot_count FROM stages WHERE md_id = ? ORDER BY ordinal"
  ).bind(mdId).all()).results || [];
  const at = stages.findIndex(s => s.ordinal === startStage);
  const order = at <= 0 ? stages : [...stages.slice(at), ...stages.slice(0, at)];

  const members = ((await env.DB.prepare(
    "SELECT id FROM entrants WHERE squad_id = ?"
  ).bind(squadId).all()).results || []).map(r => r.id);

  const have = new Map();          // stageId -> { entrantId -> recorded }
  if (members.length) {
    const marks = members.map(() => "?").join(",");
    for (const c of (await env.DB.prepare(
      `SELECT stage_id, entrant_id, recorded FROM score_cards WHERE entrant_id IN (${marks})`
    ).bind(...members).all()).results || []) {
      if (!have.has(c.stage_id)) have.set(c.stage_id, new Map());
      have.get(c.stage_id).set(c.entrant_id, c.recorded);
    }
  }

  const complete = new Set();
  for (const st of order) {
    const m = have.get(st.id);
    if (members.every(id => (m?.get(id) ?? 0) >= st.shot_count)) complete.add(st.id);
  }

  const open = new Set();
  let blocked = false;
  for (const st of order) {
    if (!blocked || have.has(st.id)) open.add(st.id);
    if (!blocked && !complete.has(st.id)) blocked = true;
  }
  return { order, open, complete };
}

/* ------------------------------------------------------------------ */
/* Who is who                                                          */
/* ------------------------------------------------------------------ */

/** Names compared without case, accents or punctuation, so "Jay  O'Neil" and
 *  "jay oneil" are the same name. */
const normName = n => String(n || "").toLowerCase().normalize("NFKD")
  .replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9 ]+/g, " ").replace(/\s+/g, " ").trim();

/**
 * Could these two names be the same person?
 *
 * Deliberately cautious. Every word of the shorter name appearing in the longer
 * one counts, so a scorer who types just "Jay" is treated as possibly being
 * "Jay Smith" and also "Jay Brown", and is kept away from both cards. A scorer
 * typing "Jay Brown" is not blocked from "Jay Smith". The cost of a false match
 * is that somebody else has to score that one card; the cost of a miss is a
 * competitor scoring themselves, which is what this exists to prevent.
 */
function sameIdentity(a, b) {
  const A = normName(a).split(" ").filter(Boolean);
  const B = normName(b).split(" ").filter(Boolean);
  if (!A.length || !B.length) return false;
  const [short, long] = A.length <= B.length ? [A, B] : [B, A];
  return short.every(t => long.includes(t));
}

/** Two entrants with the same name must still be told apart on screen. New
 *  duplicates are refused when a roster is built; this covers any that already
 *  exist. The first keeps the plain name, later ones are numbered. */
function distinctNames(entrants) {
  const seen = new Map(), out = new Map();
  for (const e of [...entrants].sort((a, b) => a.id - b.id)) {
    const k = normName(e.name);
    const n = (seen.get(k) || 0) + 1;
    seen.set(k, n);
    out.set(e.id, n === 1 ? e.name : `${e.name} (${n})`);
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Standings                                                           */
/* ------------------------------------------------------------------ */

/** Aggregates a competitor's relays according to the discipline's setting.
 *  "best" and "best N" follow the winner direction: for group size, best
 *  means smallest. */
function aggregate(scores, md) {
  const vals = scores.filter(v => v !== null && v !== undefined);
  if (!vals.length) return null;
  const low = md.winner === "lowest";

  switch (md.aggregation) {
    case "best":
      return low ? Math.min(...vals) : Math.max(...vals);
    case "average":
      return vals.reduce((a, b) => a + b, 0) / vals.length;
    case "bestn": {
      const n = Math.min(md.best_n || vals.length, vals.length);
      const sorted = [...vals].sort((a, b) => (low ? a - b : b - a));
      return sorted.slice(0, n).reduce((a, b) => a + b, 0);
    }
    default:
      return vals.reduce((a, b) => a + b, 0);
  }
}

/**
 * Builds the standings for one discipline.
 *
 * Stage mode: hits over the whole match. A stage nobody recorded counts as all
 * misses, which is why the denominator is always every stage's shot count —
 * a competitor cannot improve their percentage by having a stage go missing.
 *
 * Ties are left as ties. Placings run 1, 2, 2, 4. Where the director has
 * declared a placing it replaces the computed one and is marked as declared,
 * so nobody mistakes a judgement call for arithmetic.
 */
async function buildStandings(env, md) {
  const entrants = (await env.DB.prepare(
    `SELECT e.id, e.name, e.class, e.squad_id, s.name AS squad_name
       FROM entrants e LEFT JOIN squads s ON s.id = e.squad_id
      WHERE e.md_id = ? ORDER BY e.name, e.id`
  ).bind(md.id).all()).results || [];
  const shown = distinctNames(entrants);
  for (const e of entrants) e.name = shown.get(e.id);

  const declared = new Map(
    ((await env.DB.prepare(
      "SELECT entrant_id, place, declared_by FROM declared_places WHERE md_id = ?"
    ).bind(md.id).all()).results || []).map(r => [r.entrant_id, r])
  );

  let rows;
  let possible = null;

  if (md.mode === "stages") {
    const stages = (await env.DB.prepare(
      "SELECT id, ordinal, name, shot_count FROM stages WHERE md_id = ? ORDER BY ordinal"
    ).bind(md.id).all()).results || [];
    possible = stages.reduce((a, s) => a + s.shot_count, 0);

    const cards = (await env.DB.prepare(
      "SELECT stage_id, entrant_id, hit_count, recorded FROM score_cards WHERE md_id = ?"
    ).bind(md.id).all()).results || [];

    const byEntrant = new Map();
    for (const c of cards) {
      const e = byEntrant.get(c.entrant_id) || { hits: 0, recorded: 0, stages: {} };
      e.hits += c.hit_count;
      e.recorded += c.recorded;
      e.stages[c.stage_id] = c.hit_count;
      byEntrant.set(c.entrant_id, e);
    }

    rows = entrants.map(e => {
      const t = byEntrant.get(e.id) || { hits: 0, recorded: 0, stages: {} };
      /* Nobody who has not been scored on a single shot is ranked. A hit count
         of zero means "has shot and missed"; no recorded shots means "has not
         started", and showing that as 0/100 in 2nd place tells spectators and
         the director something that is not true. */
      const started = t.recorded > 0;
      return {
        entrant_id: e.id, name: e.name, class: e.class,
        squad_id: e.squad_id, squad_name: e.squad_name,
        value: started ? t.hits : null,
        display: started ? `${t.hits}/${possible}` : "—",
        recorded: t.recorded,
        complete: possible > 0 && t.recorded >= possible,
        per_stage: stages.map(s => ({ stage_id: s.id, ordinal: s.ordinal, hits: t.stages[s.id] ?? null }))
      };
    });
    rows.sort((a, b) => {
      if (a.value === null && b.value === null) return 0;
      if (a.value === null) return 1;
      if (b.value === null) return -1;
      return b.value - a.value;
    });

  } else {
    const scores = (await env.DB.prepare(
      "SELECT entrant_id, relay, score, x_count FROM direct_scores WHERE md_id = ? ORDER BY relay"
    ).bind(md.id).all()).results || [];

    const byEntrant = new Map();
    for (const s of scores) {
      const e = byEntrant.get(s.entrant_id) || { relays: [], x: 0, count: 0 };
      e.relays.push({ relay: s.relay, score: s.score, x_count: s.x_count });
      e.x += s.x_count || 0;
      if (s.score !== null) e.count++;
      byEntrant.set(s.entrant_id, e);
    }

    const dp = md.decimals || 0;
    rows = entrants.map(e => {
      const t = byEntrant.get(e.id) || { relays: [], x: 0, count: 0 };
      const agg = aggregate(t.relays.map(r => r.score), md);
      const shown = agg === null ? null : Number(agg.toFixed(dp));
      return {
        entrant_id: e.id, name: e.name, class: e.class,
        squad_id: e.squad_id, squad_name: e.squad_name,
        value: agg,
        display: shown === null ? "—" : (t.x ? `${shown.toFixed(dp)}-${t.x}X` : shown.toFixed(dp)),
        x_count: t.x,
        relays: t.relays,
        complete: t.count >= (md.relays || 1)
      };
    });

    // Unscored competitors sort last regardless of direction — they aren't
    // winning by having no number.
    const low = md.winner === "lowest";
    rows.sort((a, b) => {
      if (a.value === null && b.value === null) return 0;
      if (a.value === null) return 1;
      if (b.value === null) return -1;
      return low ? a.value - b.value : b.value - a.value;
    });
  }

  /* Placings.
   *
   * A declaration is the director's judgement and it wins outright: the
   * competitor takes the place stated, and everyone else moves around them.
   * That is the whole point of the tick box — two competitors tie, the
   * director picks one, and the other has to drop to second. Without the
   * shuffle the declaration would do nothing.
   *
   * Everyone not declared is ranked on the numbers alone, and equal numbers
   * still share a place. The system never breaks a tie by itself. */
  for (const r of rows) {
    const d = declared.get(r.entrant_id);
    if (d) { r.declared = true; r.declared_by = d.declared_by; r.place = d.place; }
    else r.declared = false;
  }

  const claimed = rows.filter(r => r.declared).sort((a, b) => a.place - b.place);
  const open = rows.filter(r => !r.declared);          // already in value order
  const atPlace = new Map(claimed.map(r => [r.place, r]));

  const order = [];
  let next = 0;
  for (let pos = 1; order.length < rows.length && pos <= rows.length; pos++) {
    if (atPlace.has(pos)) order.push(atPlace.get(pos));
    else if (next < open.length) order.push(open[next++]);
  }
  // A declaration numbered beyond the field size still has to appear somewhere.
  for (const r of rows) if (!order.includes(r)) order.push(r);

  let lastValue, lastPlace;
  order.forEach((r, i) => {
    if (r.declared) { lastValue = undefined; return; }
    if (r.value === null) { r.place = null; return; }
    if (lastValue !== undefined && r.value === lastValue) r.place = lastPlace;
    else { r.place = i + 1; lastPlace = r.place; lastValue = r.value; }
  });

  return { rows: order, possible };
}

/* ------------------------------------------------------------------ */
/* Director routes                                                     */
/* ------------------------------------------------------------------ */

/** The director's whole view: every discipline, its stages, its squads with
 *  their codes, and the roster. Squad codes appear here and nowhere else. */
async function getMatch(request, env, H) {
  const code = new URL(request.url).searchParams.get("code");
  const ev = await asDirector(env, code, H);
  if (!ev) return H.fail("That code isn't recognised.", 404);

  const mds = (await env.DB.prepare(
    "SELECT * FROM match_disciplines WHERE event_id = ? ORDER BY discipline"
  ).bind(ev.id).all()).results || [];

  const out = [];
  for (const md of mds) {
    const stages = (await env.DB.prepare(
      "SELECT id, ordinal, name, shot_count FROM stages WHERE md_id = ? ORDER BY ordinal"
    ).bind(md.id).all()).results || [];

    const squads = (await env.DB.prepare(
      `SELECT s.id, s.ordinal, s.name, s.code, s.scorer_name, s.start_stage,
              (SELECT COUNT(*) FROM entrants x WHERE x.squad_id = s.id) AS entrants
         FROM squads s WHERE s.md_id = ? ORDER BY s.ordinal`
    ).bind(md.id).all()).results || [];

    const entrants = (await env.DB.prepare(
      "SELECT id, name, class, squad_id FROM entrants WHERE md_id = ? ORDER BY name"
    ).bind(md.id).all()).results || [];

    // Progress, so the director can see at a glance which squad is behind.
    let progress = null;
    if (md.mode === "stages") {
      const possible = stages.reduce((a, s) => a + s.shot_count, 0) * entrants.length;
      const done = (await env.DB.prepare(
        "SELECT COALESCE(SUM(recorded),0) AS n FROM score_cards WHERE md_id = ?"
      ).bind(md.id).first())?.n || 0;
      progress = { done, possible };
    } else {
      const possible = entrants.length * (md.relays || 1);
      const done = (await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM direct_scores WHERE md_id = ? AND score IS NOT NULL"
      ).bind(md.id).first())?.n || 0;
      progress = { done, possible };
    }

    out.push({ ...md, stages, squads, entrants, progress });
  }

  return H.json({
    event: {
      id: ev.id, name: ev.name, start_date: ev.start_date, end_date: ev.end_date,
      venue: ev.venue, city: ev.city, state: ev.state,
      disciplines: H.safeParse(ev.disciplines)
    },
    match_disciplines: out
  }, 200, { "cache-control": "no-store" });
}

/** Creates or reconfigures one discipline. Locked once the match is live, so
 *  the rules cannot change underneath scores that already exist. */
async function saveDiscipline(request, env, H, body) {
  const ev = await asDirector(env, body.code, H);
  if (!ev) return H.fail("That code isn't recognised.", 404);

  const discipline = clean(body.discipline, 80);
  if (!discipline) return H.fail("Choose a discipline.");
  if (!H.safeParse(ev.disciplines).includes(discipline))
    return H.fail(`"${discipline}" isn't one of this event's disciplines.`);

  const mode = String(body.mode || "");
  if (!MODES.has(mode)) return H.fail("Choose stage scoring or direct entry.");

  const existing = await env.DB.prepare(
    "SELECT * FROM match_disciplines WHERE event_id = ? AND discipline = ?"
  ).bind(ev.id, discipline).first();

  if (existing && existing.state !== "setup" && existing.mode !== mode)
    return H.fail("The scoring mode can't change once the match has opened.");

  let cfg = {
    score_type: null, winner: "highest", decimals: 0, max_score: null,
    shots_fired: null, relays: 1, aggregation: "sum", best_n: null
  };

  if (mode === "direct") {
    const st = String(body.score_type || "points");
    if (!SCORE_TYPES.has(st)) return H.fail("Unrecognised score type.");
    const winner = body.winner === "lowest" ? "lowest" : "highest";
    const decimals = Math.min(Math.max(asInt(body.decimals) ?? 0, 0), 4);
    const relays = Math.min(Math.max(asInt(body.relays) ?? 1, 1), 20);
    const aggregation = String(body.aggregation || "sum");
    if (!AGGREGATIONS.has(aggregation)) return H.fail("Unrecognised aggregation.");
    let best_n = null;
    if (aggregation === "bestn") {
      best_n = asInt(body.best_n);
      if (!best_n || best_n < 1 || best_n > relays)
        return H.fail(`Best-of has to be between 1 and ${relays}.`);
    }
    cfg = {
      score_type: st, winner, decimals,
      max_score: asInt(body.max_score),
      shots_fired: asInt(body.shots_fired),
      relays, aggregation, best_n
    };
  }

  const live_public = body.live_public ? 1 : 0;

  if (existing) {
    await env.DB.prepare(
      `UPDATE match_disciplines SET mode=?, live_public=?, score_type=?, winner=?,
              decimals=?, max_score=?, shots_fired=?, relays=?, aggregation=?, best_n=?
        WHERE id=?`
    ).bind(mode, live_public, cfg.score_type, cfg.winner, cfg.decimals, cfg.max_score,
           cfg.shots_fired, cfg.relays, cfg.aggregation, cfg.best_n, existing.id).run();
    return H.json({ ok: true, id: existing.id });
  }

  const res = await env.DB.prepare(
    `INSERT INTO match_disciplines
       (event_id, discipline, mode, live_public, score_type, winner, decimals,
        max_score, shots_fired, relays, aggregation, best_n)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(ev.id, discipline, mode, live_public, cfg.score_type, cfg.winner, cfg.decimals,
         cfg.max_score, cfg.shots_fired, cfg.relays, cfg.aggregation, cfg.best_n).run();

  return H.json({ ok: true, id: res.meta.last_row_id });
}

/** Loads a discipline and proves it belongs to the event the code opened. */
async function ownedDiscipline(env, eventId, mdId) {
  const id = asInt(mdId);
  if (!id) return null;
  return await env.DB.prepare(
    "SELECT * FROM match_disciplines WHERE id = ? AND event_id = ?"
  ).bind(id, eventId).first();
}

/** Replaces the stage list. Refused once scores exist, because renumbering
 *  stages under recorded cards would silently move hits between them. */
async function saveStages(request, env, H, body) {
  const ev = await asDirector(env, body.code, H);
  if (!ev) return H.fail("That code isn't recognised.", 404);
  const md = await ownedDiscipline(env, ev.id, body.md_id);
  if (!md) return H.fail("That discipline isn't part of this event.", 404);
  if (md.mode !== "stages") return H.fail("This discipline doesn't use stages.");

  const list = Array.isArray(body.stages) ? body.stages : [];
  if (!list.length) return H.fail("Add at least one stage.");
  if (list.length > MAX_STAGES) return H.fail(`No more than ${MAX_STAGES} stages.`);

  const scored = (await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM score_cards WHERE md_id = ?"
  ).bind(md.id).first())?.n || 0;
  if (scored) return H.fail("Scores have already been entered, so the stages can't be rebuilt. Edit an individual stage instead.");

  const stmts = [env.DB.prepare("DELETE FROM stages WHERE md_id = ?").bind(md.id)];
  list.forEach((s, i) => {
    const shots = asInt(s.shot_count);
    if (!shots || shots < 1 || shots > MAX_SHOTS) throw new RangeError(`Stage ${i + 1} needs between 1 and ${MAX_SHOTS} shots.`);
    stmts.push(env.DB.prepare(
      "INSERT INTO stages (md_id, ordinal, name, shot_count) VALUES (?,?,?,?)"
    ).bind(md.id, i + 1, clean(s.name, 60) || `Stage ${i + 1}`, shots));
  });

  await env.DB.batch(stmts);
  return H.json({ ok: true, stages: list.length });
}

function makeCode(H) { return H.makeResultsCode(); }

/** Squads and their codes. Rotating a code revokes exactly one squad's link
 *  and leaves every other squad working. */
async function squadAction(request, env, H, body) {
  const ev = await asDirector(env, body.code, H);
  if (!ev) return H.fail("That code isn't recognised.", 404);
  const md = await ownedDiscipline(env, ev.id, body.md_id);
  if (!md) return H.fail("That discipline isn't part of this event.", 404);

  const action = String(body.action || "");

  if (action === "create") {
    const n = Math.min(Math.max(asInt(body.count) ?? 1, 1), MAX_SQUADS);
    const top = (await env.DB.prepare(
      "SELECT COALESCE(MAX(ordinal),0) AS m, COUNT(*) AS c FROM squads WHERE md_id = ?"
    ).bind(md.id).first()) || { m: 0, c: 0 };
    if (top.c + n > MAX_SQUADS) return H.fail(`No more than ${MAX_SQUADS} squads.`);

    const stmts = [];
    for (let i = 1; i <= n; i++) {
      stmts.push(env.DB.prepare(
        "INSERT INTO squads (md_id, ordinal, name, code) VALUES (?,?,?,?)"
      ).bind(md.id, top.m + i, `Squad ${top.m + i}`, makeCode(H)));
    }
    await env.DB.batch(stmts);
    return H.json({ ok: true, created: n });
  }

  const squad = await env.DB.prepare(
    "SELECT * FROM squads WHERE id = ? AND md_id = ?"
  ).bind(asInt(body.squad_id), md.id).first();
  if (!squad) return H.fail("That squad isn't part of this discipline.", 404);

  if (action === "rename") {
    const name = clean(body.name, 60);
    if (!name) return H.fail("Give the squad a name.");
    await env.DB.prepare("UPDATE squads SET name = ? WHERE id = ?").bind(name, squad.id).run();
    return H.json({ ok: true });
  }

  if (action === "set_start") {
    const o = asInt(body.stage_ordinal);
    const ok = await env.DB.prepare("SELECT 1 FROM stages WHERE md_id = ? AND ordinal = ?")
      .bind(md.id, o).first();
    if (!ok) return H.fail("That stage doesn't exist.");
    await env.DB.prepare("UPDATE squads SET start_stage = ? WHERE id = ?").bind(o, squad.id).run();
    return H.json({ ok: true });
  }

  if (action === "reshuffle") {
    const n = (await env.DB.prepare("SELECT COUNT(*) AS n FROM score_cards WHERE md_id = ?")
      .bind(md.id).first())?.n || 0;
    if (n) return H.fail("Scoring has started, so the starting stages are locked in.");
    await env.DB.prepare("UPDATE squads SET start_stage = NULL WHERE md_id = ?").bind(md.id).run();
    await assignStartStages(env, md.id);
    return H.json({ ok: true });
  }

  if (action === "rotate") {
    const fresh = makeCode(H);
    await env.DB.prepare("UPDATE squads SET code = ? WHERE id = ?").bind(fresh, squad.id).run();
    return H.json({ ok: true, code: fresh });
  }

  if (action === "delete") {
    const n = (await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM score_cards WHERE squad_id = ?"
    ).bind(squad.id).first())?.n || 0;
    if (n) return H.fail("That squad has scores recorded. Move its competitors first.");
    await env.DB.prepare("DELETE FROM squads WHERE id = ?").bind(squad.id).run();
    return H.json({ ok: true });
  }

  return H.fail("Unrecognised action.");
}

/** The roster. Competitors may be added one at a time or pasted in a block,
 *  and moved between squads at any point — moving someone does not disturb
 *  scores already recorded against them. */
async function entrantAction(request, env, H, body) {
  const ev = await asDirector(env, body.code, H);
  if (!ev) return H.fail("That code isn't recognised.", 404);
  const md = await ownedDiscipline(env, ev.id, body.md_id);
  if (!md) return H.fail("That discipline isn't part of this event.", 404);

  const action = String(body.action || "");

  if (action === "add") {
    const names = Array.isArray(body.names)
      ? body.names
      : String(body.names || "").split(/\r?\n/);
    const rows = names.map(n => clean(n, 120)).filter(Boolean);
    if (!rows.length) return H.fail("No names found.");

    const have = (await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM entrants WHERE md_id = ?"
    ).bind(md.id).first())?.n || 0;
    if (have + rows.length > MAX_ENTRANTS) return H.fail(`No more than ${MAX_ENTRANTS} competitors.`);

    let squadId = asInt(body.squad_id);
    if (squadId) {
      const ok = await env.DB.prepare(
        "SELECT id FROM squads WHERE id = ? AND md_id = ?"
      ).bind(squadId, md.id).first();
      if (!ok) return H.fail("That squad isn't part of this discipline.", 404);
    } else squadId = null;

    /* Two people with the same name cannot be told apart on a score card, in
       the standings or in the published results, so the second is refused until
       the director adds something that separates them. */
    const taken = new Set(((await env.DB.prepare(
      "SELECT name FROM entrants WHERE md_id = ?"
    ).bind(md.id).all()).results || []).map(r => normName(r.name)));
    const clashes = [];
    for (const n of rows) {
      const k = normName(n);
      if (taken.has(k)) clashes.push(n); else taken.add(k);
    }
    if (clashes.length)
      return H.fail(`${clashes.map(n => `"${n}"`).join(", ")} ${clashes.length === 1 ? "is" : "are"} already in this match. ` +
        `If ${clashes.length === 1 ? "it's a different person" : "they're different people"}, add something to tell them apart — ` +
        `a middle initial, "Jr." or a number — so scorers and the standings can too.`);

    await env.DB.batch(rows.map(name => env.DB.prepare(
      "INSERT INTO entrants (md_id, squad_id, name, class) VALUES (?,?,?,?)"
    ).bind(md.id, squadId, name, clean(body.class, 60))));

    return H.json({ ok: true, added: rows.length });
  }

  const entrant = await env.DB.prepare(
    "SELECT * FROM entrants WHERE id = ? AND md_id = ?"
  ).bind(asInt(body.entrant_id), md.id).first();
  if (!entrant) return H.fail("That competitor isn't on this roster.", 404);

  if (action === "assign") {
    let squadId = asInt(body.squad_id);
    if (squadId) {
      const ok = await env.DB.prepare(
        "SELECT id FROM squads WHERE id = ? AND md_id = ?"
      ).bind(squadId, md.id).first();
      if (!ok) return H.fail("That squad isn't part of this discipline.", 404);
    } else squadId = null;
    await env.DB.prepare("UPDATE entrants SET squad_id = ? WHERE id = ?")
      .bind(squadId, entrant.id).run();
    return H.json({ ok: true });
  }

  if (action === "rename") {
    const name = clean(body.name, 120);
    if (!name) return H.fail("A name is required.");
    const others = (await env.DB.prepare(
      "SELECT name FROM entrants WHERE md_id = ? AND id <> ?"
    ).bind(md.id, entrant.id).all()).results || [];
    if (others.some(r => normName(r.name) === normName(name)))
      return H.fail(`"${name}" is already in this match. Add something to tell them apart, like a middle initial or "Jr."`);
    await env.DB.prepare("UPDATE entrants SET name = ?, class = ? WHERE id = ?")
      .bind(name, clean(body.class, 60), entrant.id).run();
    return H.json({ ok: true });
  }

  if (action === "remove") {
    await env.DB.prepare("DELETE FROM entrants WHERE id = ?").bind(entrant.id).run();
    return H.json({ ok: true });
  }

  return H.fail("Unrecognised action.");
}

/** setup → live → complete. Opening a match checks it can actually be scored. */
async function setState(request, env, H, body) {
  const ev = await asDirector(env, body.code, H);
  if (!ev) return H.fail("That code isn't recognised.", 404);
  const md = await ownedDiscipline(env, ev.id, body.md_id);
  if (!md) return H.fail("That discipline isn't part of this event.", 404);

  const state = String(body.state || "");
  if (!STATES.has(state)) return H.fail("Unrecognised match state.");

  if (state === "live") {
    const entrants = (await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM entrants WHERE md_id = ?"
    ).bind(md.id).first())?.n || 0;
    if (!entrants) return H.fail("Add competitors before opening the match.");

    if (md.mode === "stages") {
      const stages = (await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM stages WHERE md_id = ?"
      ).bind(md.id).first())?.n || 0;
      if (!stages) return H.fail("Set up the stages before opening the match.");
      const squads = (await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM squads WHERE md_id = ?"
      ).bind(md.id).first())?.n || 0;
      if (!squads) return H.fail("Create at least one squad so scorers have a code.");
    }
  }

  const live_public = body.live_public === undefined
    ? md.live_public
    : (body.live_public ? 1 : 0);

  await env.DB.prepare("UPDATE match_disciplines SET state = ?, live_public = ? WHERE id = ?")
    .bind(state, live_public, md.id).run();

  // Opening the match draws each squad's starting stage.
  if (state === "live" && md.mode === "stages") await assignStartStages(env, md.id);

  return H.json({ ok: true, state, live_public });
}

/** The director's tick box. Ties are never broken by the system; a placing is
 *  either computed or declared, and the standings say which. */
async function declarePlace(request, env, H, body) {
  const ev = await asDirector(env, body.code, H);
  if (!ev) return H.fail("That code isn't recognised.", 404);
  const md = await ownedDiscipline(env, ev.id, body.md_id);
  if (!md) return H.fail("That discipline isn't part of this event.", 404);
  if (md.state === "complete") return H.fail("The match is closed. Reopen it to change a placing.");

  const entrant = await env.DB.prepare(
    "SELECT id FROM entrants WHERE id = ? AND md_id = ?"
  ).bind(asInt(body.entrant_id), md.id).first();
  if (!entrant) return H.fail("That competitor isn't on this roster.", 404);

  if (body.place === null || body.place === undefined || body.place === false) {
    await env.DB.prepare("DELETE FROM declared_places WHERE md_id = ? AND entrant_id = ?")
      .bind(md.id, entrant.id).run();
    return H.json({ ok: true, declared: false });
  }

  const place = asInt(body.place);
  if (!place || place < 1) return H.fail("A placing has to be 1 or more.");

  await env.DB.prepare(
    `INSERT INTO declared_places (md_id, entrant_id, place, declared_by)
     VALUES (?,?,?,?)
     ON CONFLICT(md_id, entrant_id) DO UPDATE SET
       place = excluded.place, declared_by = excluded.declared_by,
       declared_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')`
  ).bind(md.id, entrant.id, place, clean(body.by, 80)).run();

  return H.json({ ok: true, declared: true, place });
}

/**
 * One score, typed by the director in the console.
 *
 * Squad sync is scoped to a squad code and a director does not hold one — they
 * hold the event code — so a small bench rest match with no squad scorers had
 * no way in at all. This is that way in: same validation as sync, same history
 * trail, but authoritative. The director is one person at one keyboard looking
 * at the standings, so a version clash is not a real risk and last write wins
 * rather than raising a conflict nobody else could resolve.
 */
async function enterScore(request, env, H, body) {
  const ev = await asDirector(env, body.code, H);
  if (!ev) return H.fail("That code isn't recognised.", 404);
  const md = await ownedDiscipline(env, ev.id, body.md_id);
  if (!md) return H.fail("That discipline isn't part of this event.", 404);
  if (md.mode !== "direct") return H.fail("This discipline is scored stage by stage.");
  if (md.state === "setup") return H.fail("Open the match before entering scores.", 409);

  const entrantId = asInt(body.entrant_id);
  const entrant = await env.DB.prepare(
    "SELECT id FROM entrants WHERE id = ? AND md_id = ?"
  ).bind(entrantId, md.id).first();
  if (!entrant) return H.fail("That competitor isn't in this discipline.", 404);

  const relay = Math.min(Math.max(asInt(body.relay) ?? 1, 1), md.relays || 1);

  const score = body.score === null || body.score === undefined || String(body.score).trim() === ""
    ? null : Number(body.score);
  if (score !== null && !Number.isFinite(score)) return H.fail("That score isn't a number.");
  if (score !== null && score < 0) return H.fail("A score can't be negative.");
  if (score !== null && md.max_score && md.score_type === "points" && score > md.max_score)
    return H.fail(`The perfect score for this match is ${md.max_score}.`);

  const x = body.x_count === null || body.x_count === undefined || String(body.x_count).trim() === ""
    ? null : asInt(body.x_count);
  if (x !== null && (x < 0 || (md.shots_fired && x > md.shots_fired)))
    return H.fail("That X count isn't possible for this course of fire.");

  const who = clean(body.by, 80) || "Match director";
  const existing = await env.DB.prepare(
    "SELECT * FROM direct_scores WHERE entrant_id = ? AND relay = ?"
  ).bind(entrantId, relay).first();

  let refId, version;
  if (existing) {
    refId = existing.id;
    version = existing.version + 1;
    await env.DB.prepare(
      `UPDATE direct_scores SET score=?, x_count=?, version=?, scored_by=?,
              scored_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'), device_id='console'
        WHERE id=?`
    ).bind(score, x, version, who, refId).run();
  } else {
    refId = crypto.randomUUID();
    version = 1;
    await env.DB.prepare(
      `INSERT INTO direct_scores (id, md_id, entrant_id, relay, score, x_count,
                                  version, scored_by, device_id)
       VALUES (?,?,?,?,?,?,1,?,'console')`
    ).bind(refId, md.id, entrantId, relay, score, x, who).run();
  }

  await env.DB.prepare(
    `INSERT INTO score_history (kind, ref_id, md_id, version, payload, actor_name, via_code, device_id)
     VALUES ('direct',?,?,?,?,?,'console','console')`
  ).bind(refId, md.id, version, JSON.stringify({ relay, score, x_count: x }), who).run();

  return H.json({ ok: true, version });
}

async function directorStandings(request, env, H) {
  const url = new URL(request.url);
  const ev = await asDirector(env, url.searchParams.get("code"), H);
  if (!ev) return H.fail("That code isn't recognised.", 404);
  const md = await ownedDiscipline(env, ev.id, url.searchParams.get("md"));
  if (!md) return H.fail("That discipline isn't part of this event.", 404);

  const { rows, possible } = await buildStandings(env, md);

  /* The witnessed-edit log rides along with the standings so the console's
     five-second refresh picks up a new edit as it happens. */
  const edits = ((await env.DB.prepare(
    `SELECT x.id, x.kind, x.stage_id, x.relay, x.version, x.witness, x.edited_by,
            x.before, x.after, x.edited_at, e.name AS competitor, st.name AS stage
       FROM score_edits x
       JOIN entrants e ON e.id = x.entrant_id
       LEFT JOIN stages st ON st.id = x.stage_id
      WHERE x.md_id = ? ORDER BY x.id DESC LIMIT 300`
  ).bind(md.id).all()).results || []).map(r => ({
    ...r,
    before: (() => { try { return JSON.parse(r.before); } catch { return {}; } })(),
    after:  (() => { try { return JSON.parse(r.after);  } catch { return {}; } })()
  }));

  return H.json({
    discipline: md.discipline, mode: md.mode, state: md.state,
    live_public: md.live_public, possible, standings: rows, edits
  }, 200, { "cache-control": "no-store" });
}

/**
 * Copies the finished standings into the results table, which is what the
 * public results view and the national rankings read. Only this discipline's
 * rows are replaced, so publishing one discipline never disturbs another.
 */
async function publish(request, env, H, body) {
  const ev = await asDirector(env, body.code, H);
  if (!ev) return H.fail("That code isn't recognised.", 404);
  const md = await ownedDiscipline(env, ev.id, body.md_id);
  if (!md) return H.fail("That discipline isn't part of this event.", 404);

  const { rows, possible } = await buildStandings(env, md);
  const scored = rows.filter(r => r.place !== null);
  if (!scored.length) return H.fail("There's nothing to publish yet.");

  /* Hits, and the targets that were there to be hit.
   *
   * The national rankings are built on season accuracy, so every published
   * result carries both numbers where they exist. Live scoring knows them
   * exactly — it counted each tap against each stage's shot count — which is
   * the one place this can be recorded without asking anyone to type it.
   *
   * Where there is no countable maximum the pair is left null rather than
   * guessed at. A group size of 0.245 inches has no "available", and writing a
   * zero there would read as a shooter who hit nothing. */
  const availableFor = () => {
    if (md.mode === "stages") return possible || null;
    if (md.score_type !== "points" || !md.max_score) return null;
    /* max_score is the perfect score for the whole match, stated once by the
       director — not a per-relay figure to be multiplied up. A director who
       adds three relays together enters the total the three are worth, and the
       settings panel says so when relays are in play. */
    return md.max_score;
  };
  const maxAvailable = availableFor();

  const stmts = [
    env.DB.prepare("DELETE FROM results WHERE event_id = ? AND discipline = ?")
      .bind(ev.id, md.discipline)
  ];

  for (const [i, r] of scored.entries()) {
    const shooterId = await H.resolveShooter(env, r.name);
    // r.value is hits in stage mode and the aggregated score in direct mode —
    // in both cases it is the number that sits over the maximum.
    const hits = maxAvailable !== null && typeof r.value === "number" ? r.value : null;

    stmts.push(env.DB.prepare(
      `INSERT INTO results (event_id, discipline, place, competitor, score, class,
                            sort_order, shooter_id, points, field_size, hits, available,
                            x_count)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(ev.id, md.discipline, r.place, r.name, r.display, r.class,
           i + 1, shooterId, H.pointsForPlace(r.place), scored.length,
           hits, hits === null ? null : maxAvailable,
           Number.isFinite(r.x_count) ? r.x_count : null));
  }

  stmts.push(env.DB.prepare(
    "UPDATE events SET results_updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?"
  ).bind(ev.id));
  stmts.push(env.DB.prepare(
    "UPDATE match_disciplines SET state = 'complete' WHERE id = ?"
  ).bind(md.id));

  await env.DB.batch(stmts);
  return H.json({ ok: true, published: scored.length });
}

/* ------------------------------------------------------------------ */
/* Squad routes                                                        */
/* ------------------------------------------------------------------ */

/**
 * Everything one scorer's phone needs, in a single response, so the page can
 * be opened once at the start of the day and then work with no signal at all.
 * It contains this squad's competitors and no one else's.
 */
async function getSquad(request, env, H) {
  const code = new URL(request.url).searchParams.get("code");
  const sq = await asSquad(env, code);
  if (!sq || sq.status !== "approved") return H.fail("That code isn't recognised.", 404);

  const md = await env.DB.prepare("SELECT * FROM match_disciplines WHERE id = ?")
    .bind(sq.md_id).first();

  /* Stages come back in this squad's own order, starting at the stage it was
     drawn, so the phone's first stage is always where this squad begins. */
  let stages = [], startStage = null;
  if (md.mode === "stages") {
    if (md.state === "live") await assignStartStages(env, md.id);
    startStage = (await env.DB.prepare("SELECT start_stage FROM squads WHERE id = ?")
      .bind(sq.squad_id).first())?.start_stage ?? null;
    const plan = await stagePlan(env, md.id, sq.squad_id, startStage);
    stages = plan.order.map(s => ({ ...s, open: plan.open.has(s.id) }));
  }

  const entrants = (await env.DB.prepare(
    "SELECT id, name, class FROM entrants WHERE squad_id = ? ORDER BY id"
  ).bind(sq.squad_id).all()).results || [];
  {
    const everyone = (await env.DB.prepare(
      "SELECT id, name FROM entrants WHERE md_id = ?"
    ).bind(md.id).all()).results || [];
    const shown = distinctNames(everyone);
    for (const e of entrants) e.name = shown.get(e.id) || e.name;
  }

  const ids = entrants.map(e => e.id);
  let cards = [], direct = [];

  if (ids.length) {
    const marks = ids.map(() => "?").join(",");
    if (md.mode === "stages") {
      cards = (await env.DB.prepare(
        `SELECT id, stage_id, entrant_id, hits, hit_count, recorded, version, scored_by, scored_at, submitted_at
           FROM score_cards WHERE entrant_id IN (${marks})`
      ).bind(...ids).all()).results || [];
    } else {
      direct = (await env.DB.prepare(
        `SELECT id, entrant_id, relay, score, x_count, version, scored_by, scored_at, submitted_at
           FROM direct_scores WHERE entrant_id IN (${marks})`
      ).bind(...ids).all()).results || [];
    }
  }

  return H.json({
    event: {
      name: sq.event_name, start_date: sq.start_date,
      venue: sq.venue, city: sq.city, state: sq.event_state
    },
    squad: { id: sq.squad_id, name: sq.squad_name, scorer_name: sq.scorer_name, start_stage: startStage },
    discipline: {
      id: md.id, name: md.discipline, mode: md.mode, state: md.state,
      relays: md.relays, score_type: md.score_type, decimals: md.decimals,
      max_score: md.max_score, shots_fired: md.shots_fired, winner: md.winner
    },
    stages, entrants, cards, direct,
    server_time: new Date().toISOString()
  }, 200, { "cache-control": "no-store" });
}

const sameHits = (a, b) =>
  Array.isArray(a) && Array.isArray(b) && a.length === b.length &&
  a.every((v, i) => (v ?? null) === (b[i] ?? null));

/**
 * The offline queue drains here. Every item carries the version it was edited
 * from; if the server has moved on the item is refused and the server's copy
 * comes back so the scorer can compare. Nothing is overwritten silently.
 *
 * A replay of a write that already landed is recognised by its content and
 * reported as accepted, so a flaky connection retrying doesn't raise a false
 * conflict.
 */
async function sync(request, env, H, body) {
  const sq = await asSquad(env, body.code);
  if (!sq || sq.status !== "approved") return H.fail("That code isn't recognised.", 404);
  if (sq.state !== "live") return H.fail("This match isn't open for scoring.", 409);
  if (!(await rateOk(env, String(body.code)))) return H.fail("Too many updates at once. Wait a moment.", 429);

  const md = await env.DB.prepare("SELECT * FROM match_disciplines WHERE id = ?")
    .bind(sq.md_id).first();

  const scorer = clean(body.scorer_name, 80);
  const device = clean(body.device_id, 64);
  const viaCode = String(body.code || "").slice(-4);   // a hint for the audit trail, not the code

  const items = Array.isArray(body.items) ? body.items.slice(0, MAX_SYNC_ITEMS) : [];
  if (!items.length) return H.json({ ok: true, accepted: [], conflicts: [], rejected: [] });

  // The two sets this squad is allowed to touch, read fresh from the server.
  const memberRows = (await env.DB.prepare(
    "SELECT id, name FROM entrants WHERE squad_id = ?"
  ).bind(sq.squad_id).all()).results || [];
  const members = new Set(memberRows.map(r => r.id));
  const nameById = new Map(memberRows.map(r => [r.id, r.name]));

  const stageMap = new Map(((await env.DB.prepare(
    "SELECT id, shot_count FROM stages WHERE md_id = ?"
  ).bind(md.id).all()).results || []).map(r => [r.id, r.shot_count]));

  const accepted = [], conflicts = [], rejected = [];

  /* Stage order: a squad may only score the stage it is on. Recomputed from the
     database when a stage looks closed, because an earlier item in this same
     batch may have just finished the stage before it. */
  let plan = null;
  if (md.mode === "stages") {
    await assignStartStages(env, md.id);
    const start = (await env.DB.prepare("SELECT start_stage FROM squads WHERE id = ?")
      .bind(sq.squad_id).first())?.start_stage ?? null;
    var planFor = () => stagePlan(env, md.id, sq.squad_id, start);
    plan = await planFor();
  }

  /* A card or score is "submitted" once the scorer has pressed Done on it.
     Changing it afterwards needs a witness, and the change is logged. */
  const NEED_WITNESS = "This score was already submitted. Enter a witness's name to change it.";
  const logEdit = (kind, ref, entrantId, stageId, relay, version, witness, before, after) =>
    env.DB.prepare(
      `INSERT INTO score_edits (md_id, kind, ref_id, entrant_id, stage_id, relay, version,
                                witness, edited_by, device_id, before, after)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(md.id, kind, ref, entrantId, stageId, relay, version, witness, scorer, device,
           JSON.stringify(before), JSON.stringify(after)).run();

  for (const item of items) {
    const witness = clean(item.witness, 80);
    const final = item.final === true;
    const entrantId = asInt(item.entrant_id);
    if (!members.has(entrantId)) {
      rejected.push({ id: item.id, reason: "That competitor isn't in this squad." });
      continue;
    }

    /* Nobody scores their own card, and nobody witnesses their own change.
       Checked here as well as on the phone: the phone only keeps an honest
       scorer from making the mistake, this is what stops it being done on
       purpose. */
    const entrantName = nameById.get(entrantId);
    if (sameIdentity(scorer, entrantName)) {
      rejected.push({ id: item.id, reason: "You can't score your own card. Another member of the squad has to score you." });
      continue;
    }
    if (witness && (sameIdentity(witness, scorer) || sameIdentity(witness, entrantName))) {
      rejected.push({ id: item.id, reason: "The witness can't be the scorer or the competitor whose score is being changed." });
      continue;
    }

    /* ---------- stage card ---------- */
    if (md.mode === "stages") {
      const stageId = asInt(item.stage_id);
      const shots = stageMap.get(stageId);
      if (!shots) { rejected.push({ id: item.id, reason: "Unknown stage." }); continue; }

      if (!plan.open.has(stageId)) plan = await planFor();
      if (!plan.open.has(stageId)) {
        const prev = plan.order.find(s => !plan.complete.has(s.id));
        rejected.push({ id: item.id, reason: `That stage isn't open yet. Your squad is on ${prev ? prev.name : "an earlier stage"} — everyone in the squad has to be scored there first.` });
        continue;
      }

      const hits = Array.isArray(item.hits) ? item.hits : null;
      if (!hits || hits.length !== shots) {
        rejected.push({ id: item.id, reason: `Stage needs exactly ${shots} shots.` });
        continue;
      }
      const norm = hits.map(v => (v === 1 || v === true) ? 1 : (v === 0 || v === false) ? 0 : null);
      const hitCount = norm.filter(v => v === 1).length;
      const recorded = norm.filter(v => v !== null).length;
      /* A card is submitted only once every shot has a result. Pressing "Save &
         close" on a half-scored card sends what is recorded but leaves it open,
         so the scorer can carry on without a witness. */
      const cardFinal = final && recorded === shots;

      const existing = await env.DB.prepare(
        "SELECT * FROM score_cards WHERE stage_id = ? AND entrant_id = ?"
      ).bind(stageId, entrantId).first();

      if (!existing) {
        const id = String(item.id || crypto.randomUUID()).slice(0, 64);
        await env.DB.prepare(
          `INSERT INTO score_cards (id, md_id, stage_id, entrant_id, hits, hit_count,
                                    recorded, version, scored_by, squad_id, device_id, submitted_at)
           VALUES (?,?,?,?,?,?,?,1,?,?,?,${cardFinal ? "strftime('%Y-%m-%dT%H:%M:%SZ','now')" : "NULL"})`
        ).bind(id, md.id, stageId, entrantId, JSON.stringify(norm), hitCount,
               recorded, scorer, sq.squad_id, device).run();
        await env.DB.prepare(
          `INSERT INTO score_history (kind, ref_id, md_id, version, payload, actor_name, via_code, device_id)
           VALUES ('card',?,?,1,?,?,?,?)`
        ).bind(id, md.id, JSON.stringify({ hits: norm, hit_count: hitCount }), scorer, viaCode, device).run();
        accepted.push({ id: item.id, server_id: id, version: 1 });
        continue;
      }

      const base = asInt(item.base_version) ?? 0;
      if (base !== existing.version) {
        // A retry of a write that already landed looks identical — accept it.
        if (sameHits(norm, H.safeParse(existing.hits))) {
          accepted.push({ id: item.id, server_id: existing.id, version: existing.version, replay: true });
        } else {
          conflicts.push({
            id: item.id,
            yours: { hits: norm, scored_by: scorer },
            theirs: {
              id: existing.id, hits: H.safeParse(existing.hits), version: existing.version,
              scored_by: existing.scored_by, scored_at: existing.scored_at,
              submitted_at: existing.submitted_at
            }
          });
        }
        continue;
      }

      const oldHits = H.safeParse(existing.hits);
      const changed = !sameHits(norm, oldHits);
      if (existing.submitted_at && changed && !witness) {
        rejected.push({ id: item.id, reason: NEED_WITNESS });
        continue;
      }

      const nextVersion = existing.version + 1;
      await env.DB.prepare(
        `UPDATE score_cards SET hits=?, hit_count=?, recorded=?, version=?, scored_by=?,
                scored_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'), device_id=?,
                submitted_at=${cardFinal ? "COALESCE(submitted_at, strftime('%Y-%m-%dT%H:%M:%SZ','now'))" : "submitted_at"}
          WHERE id=? AND version=?`
      ).bind(JSON.stringify(norm), hitCount, recorded, nextVersion, scorer, device,
             existing.id, existing.version).run();
      if (existing.submitted_at && changed) {
        await logEdit("card", existing.id, entrantId, stageId, null, nextVersion, witness,
          { hits: oldHits, hit_count: existing.hit_count },
          { hits: norm, hit_count: hitCount });
      }
      await env.DB.prepare(
        `INSERT INTO score_history (kind, ref_id, md_id, version, payload, actor_name, via_code, device_id)
         VALUES ('card',?,?,?,?,?,?,?)`
      ).bind(existing.id, md.id, nextVersion,
             JSON.stringify({ hits: norm, hit_count: hitCount }), scorer, viaCode, device).run();
      accepted.push({ id: item.id, server_id: existing.id, version: nextVersion });
      continue;
    }

    /* ---------- direct entry ---------- */
    const relay = Math.min(Math.max(asInt(item.relay) ?? 1, 1), md.relays || 1);
    const score = item.score === null || item.score === "" || item.score === undefined
      ? null : Number(item.score);
    if (score !== null && !Number.isFinite(score)) {
      rejected.push({ id: item.id, reason: "That score isn't a number." });
      continue;
    }
    if (score !== null && md.max_score && md.score_type === "points" && score > md.max_score) {
      rejected.push({ id: item.id, reason: `The highest possible score is ${md.max_score}.` });
      continue;
    }
    if (score !== null && score < 0) {
      rejected.push({ id: item.id, reason: "A score can't be negative." });
      continue;
    }
    const x = item.x_count === null || item.x_count === "" || item.x_count === undefined
      ? null : asInt(item.x_count);
    if (x !== null && (x < 0 || (md.shots_fired && x > md.shots_fired))) {
      rejected.push({ id: item.id, reason: "That X count isn't possible for this course of fire." });
      continue;
    }

    const existing = await env.DB.prepare(
      "SELECT * FROM direct_scores WHERE entrant_id = ? AND relay = ?"
    ).bind(entrantId, relay).first();

    if (!existing) {
      const id = String(item.id || crypto.randomUUID()).slice(0, 64);
      await env.DB.prepare(
        `INSERT INTO direct_scores (id, md_id, entrant_id, relay, score, x_count,
                                    version, scored_by, device_id, submitted_at)
         VALUES (?,?,?,?,?,?,1,?,?,${final ? "strftime('%Y-%m-%dT%H:%M:%SZ','now')" : "NULL"})`
      ).bind(id, md.id, entrantId, relay, score, x, scorer, device).run();
      await env.DB.prepare(
        `INSERT INTO score_history (kind, ref_id, md_id, version, payload, actor_name, via_code, device_id)
         VALUES ('direct',?,?,1,?,?,?,?)`
      ).bind(id, md.id, JSON.stringify({ relay, score, x_count: x }), scorer, viaCode, device).run();
      accepted.push({ id: item.id, server_id: id, version: 1 });
      continue;
    }

    const base = asInt(item.base_version) ?? 0;
    if (base !== existing.version) {
      if (existing.score === score && (existing.x_count ?? null) === x) {
        accepted.push({ id: item.id, server_id: existing.id, version: existing.version, replay: true });
      } else {
        conflicts.push({
          id: item.id,
          yours: { relay, score, x_count: x, scored_by: scorer },
          theirs: {
            id: existing.id, relay: existing.relay, score: existing.score,
            x_count: existing.x_count, version: existing.version,
            scored_by: existing.scored_by, scored_at: existing.scored_at,
            submitted_at: existing.submitted_at
          }
        });
      }
      continue;
    }

    const changedD = existing.score !== score || (existing.x_count ?? null) !== x;
    if (existing.submitted_at && changedD && !witness) {
      rejected.push({ id: item.id, reason: NEED_WITNESS });
      continue;
    }

    const nextVersion = existing.version + 1;
    await env.DB.prepare(
      `UPDATE direct_scores SET score=?, x_count=?, version=?, scored_by=?,
              scored_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'), device_id=?,
              submitted_at=${final ? "COALESCE(submitted_at, strftime('%Y-%m-%dT%H:%M:%SZ','now'))" : "submitted_at"}
        WHERE id=? AND version=?`
    ).bind(score, x, nextVersion, scorer, device, existing.id, existing.version).run();
    if (existing.submitted_at && changedD) {
      await logEdit("direct", existing.id, entrantId, null, relay, nextVersion, witness,
        { score: existing.score, x_count: existing.x_count },
        { score, x_count: x });
    }
    await env.DB.prepare(
      `INSERT INTO score_history (kind, ref_id, md_id, version, payload, actor_name, via_code, device_id)
       VALUES ('direct',?,?,?,?,?,?,?)`
    ).bind(existing.id, md.id, nextVersion,
           JSON.stringify({ relay, score, x_count: x }), scorer, viaCode, device).run();
    accepted.push({ id: item.id, server_id: existing.id, version: nextVersion });
  }

  return H.json({ ok: true, accepted, conflicts, rejected }, 200, { "cache-control": "no-store" });
}

/* ------------------------------------------------------------------ */
/* Match analysis                                                      */
/* ------------------------------------------------------------------ */

/**
 * Where did the field struggle?
 *
 * Every card holds one entry per shot, so the data to answer that is already
 * on the server: for each stage and each shot, how many were attempted and how
 * many were hit. This turns the cards into that picture. It is a pure function
 * of the stages, the roster and the cards, so it can be tested without a
 * database and gives the same answer on every call.
 *
 * Nothing here judges a stage as "too hard" in absolute terms — a field target
 * course is meant to be hard, a bench rest one is not — so difficulty is
 * stated against the match's own average, with the raw numbers beside it.
 */
function analyse(stages, entrants, cards) {
  const cls = new Map(entrants.map(e => [e.id, e.class || "Unclassed"]));
  const rowsByStage = new Map(stages.map(s => [s.id, []]));
  for (const c of cards) {
    const bucket = rowsByStage.get(c.stage_id);
    if (!bucket) continue;
    let hits;
    try { hits = JSON.parse(c.hits); } catch { continue; }
    if (Array.isArray(hits)) bucket.push({ entrant: c.entrant_id, hits });
  }

  const rate = (hit, att) => att ? hit / att : null;
  const perEntrant = new Map();
  let totalHits = 0, totalAtt = 0;

  const out = stages.map(st => {
    const shots = Array.from({ length: st.shot_count }, () => ({ attempts: 0, hits: 0 }));
    const classes = {};
    const spread = Array(st.shot_count + 1).fill(0);   // how many shooters hit 0..N
    let att = 0, hit = 0, shooters = 0, perfect = 0, blank = 0;

    for (const r of rowsByStage.get(st.id)) {
      let rh = 0, ra = 0;
      r.hits.forEach((v, i) => {
        if (i >= st.shot_count || (v !== 0 && v !== 1)) return;
        shots[i].attempts++; ra++;
        if (v === 1) { shots[i].hits++; rh++; }
      });
      if (!ra) continue;                                // not started this stage
      shooters++; att += ra; hit += rh;

      const k = cls.get(r.entrant) || "Unclassed";
      const c = classes[k] || (classes[k] = { shooters: 0, attempts: 0, hits: 0 });
      c.shooters++; c.attempts += ra; c.hits += rh;

      if (ra === st.shot_count) {
        spread[rh]++;
        if (rh === st.shot_count) perfect++;
        if (rh === 0) blank++;
      }
      const pe = perEntrant.get(r.entrant) || { attempts: 0, hits: 0 };
      pe.attempts += ra; pe.hits += rh; perEntrant.set(r.entrant, pe);
    }
    totalHits += hit; totalAtt += att;

    const shotRows = shots.map((x, i) => ({ n: i + 1, attempts: x.attempts, hits: x.hits, rate: rate(x.hits, x.attempts) }));
    const scored = shotRows.filter(x => x.rate !== null);
    const hardest = scored.length ? scored.reduce((a, b) => (b.rate < a.rate ? b : a)) : null;
    const easiest = scored.length ? scored.reduce((a, b) => (b.rate > a.rate ? b : a)) : null;

    return {
      stage_id: st.id, ordinal: st.ordinal, name: st.name, shot_count: st.shot_count,
      shooters, attempts: att, hits: hit, rate: rate(hit, att),
      perfect, blank, spread,
      shots: shotRows,
      hardest_shot: hardest && hardest.n, easiest_shot: easiest && easiest.n,
      classes: Object.entries(classes).map(([name, c]) => ({
        name, shooters: c.shooters, rate: rate(c.hits, c.attempts)
      })).sort((a, b) => a.name.localeCompare(b.name))
    };
  });

  const overall = rate(totalHits, totalAtt);

  // Difficulty is relative to this match's own average.
  for (const s of out) {
    if (s.rate === null || overall === null) { s.level = null; continue; }
    const d = s.rate - overall;
    s.level = d >= 0.10 ? "easier" : d <= -0.20 ? "much_harder" : d <= -0.10 ? "harder" : "typical";
  }
  const ranked = out.filter(s => s.rate !== null).sort((a, b) => a.rate - b.rate);
  ranked.forEach((s, i) => { s.rank = i + 1; });          // 1 = hardest

  // Single shots that stood out, ignoring ones few people have attempted yet.
  const hardShots = [];
  for (const s of out) {
    const floor = Math.max(3, Math.ceil(s.shooters * 0.5));
    for (const x of s.shots)
      if (x.rate !== null && x.attempts >= floor)
        hardShots.push({ stage_id: s.stage_id, stage: s.name, n: x.n, attempts: x.attempts, hits: x.hits, rate: x.rate });
  }
  hardShots.sort((a, b) => a.rate - b.rate || a.stage_id - b.stage_id || a.n - b.n);

  /* Competitors who found the match very hard are the ones who may not come
     back, which is why the director asked for this. Only those who have shot at
     least half the course are counted, so a mid-match look is not distorted by
     people who have barely started. */
  const possible = stages.reduce((a, s) => a + s.shot_count, 0);
  const THRESHOLD = 0.4;
  let considered = 0, below = 0, finished = 0;
  for (const e of entrants) {
    const pe = perEntrant.get(e.id);
    if (!pe) continue;
    if (pe.attempts >= possible) finished++;
    if (pe.attempts * 2 < possible) continue;
    considered++;
    if (pe.hits / pe.attempts < THRESHOLD) below++;
  }

  return {
    competitors: entrants.length, finished,
    overall: { rate: overall, hits: totalHits, attempts: totalAtt, possible: possible * entrants.length },
    struggling: { threshold: THRESHOLD, considered, below },
    stages: out,
    hardest_shots: hardShots.slice(0, 8)
  };
}

async function matchAnalysis(request, env, H) {
  const url = new URL(request.url);
  const ev = await asDirector(env, url.searchParams.get("code"), H);
  if (!ev) return H.fail("That code isn't recognised.", 404);
  const md = await ownedDiscipline(env, ev.id, url.searchParams.get("md"));
  if (!md) return H.fail("That discipline isn't part of this event.", 404);

  if (md.mode !== "stages") {
    return H.json({ available: false,
      reason: "Stage and shot analysis needs a match scored shot by shot. This one is scored by total." },
      200, { "cache-control": "no-store" });
  }

  const stages = (await env.DB.prepare(
    "SELECT id, ordinal, name, shot_count FROM stages WHERE md_id = ? ORDER BY ordinal"
  ).bind(md.id).all()).results || [];
  const entrants = (await env.DB.prepare(
    "SELECT id, name, class FROM entrants WHERE md_id = ?"
  ).bind(md.id).all()).results || [];
  const cards = (await env.DB.prepare(
    "SELECT stage_id, entrant_id, hits FROM score_cards WHERE md_id = ?"
  ).bind(md.id).all()).results || [];

  const a = analyse(stages, entrants, cards);
  return H.json({
    available: true, discipline: md.discipline, state: md.state,
    // Final only once the match is closed and every competitor has a full card.
    provisional: md.state !== "complete" || a.finished < a.competitors,
    ...a
  }, 200, { "cache-control": "no-store" });
}

/* ------------------------------------------------------------------ */
/* Public route                                                        */
/* ------------------------------------------------------------------ */

/** Live standings for spectators. Only disciplines the director has opened to
 *  the public appear, and only names and scores are returned — never a code,
 *  a squad code, or anything about who is scoring. */
async function publicLive(request, env, H) {
  const url = new URL(request.url);
  const eventId = String(url.searchParams.get("event") || "");
  if (!/^[0-9a-fA-F-]{36}$/.test(eventId)) return H.fail("Unknown event.", 404);

  const ev = await env.DB.prepare(
    "SELECT id, name, start_date, venue, city, state FROM events WHERE id = ? AND status = 'approved'"
  ).bind(eventId).first();
  if (!ev) return H.fail("Unknown event.", 404);

  const mds = (await env.DB.prepare(
    `SELECT * FROM match_disciplines
      WHERE event_id = ? AND live_public = 1 AND state IN ('live','complete')
      ORDER BY discipline`
  ).bind(eventId).all()).results || [];

  const out = [];
  for (const md of mds) {
    const { rows, possible } = await buildStandings(env, md);
    out.push({
      discipline: md.discipline, mode: md.mode, state: md.state, possible,
      standings: rows.map(r => ({
        place: r.place, name: r.name, class: r.class,
        squad_name: r.squad_name, display: r.display,
        complete: r.complete, declared: !!r.declared
      }))
    });
  }

  return H.json({ event: ev, disciplines: out }, 200,
    { "cache-control": "public, max-age=15" });
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

export async function handleScoring(request, env, path, method, H) {
  // Director reads
  if (path === "/api/scoring/match"     && method === "GET") return await getMatch(request, env, H);
  if (path === "/api/scoring/standings" && method === "GET") return await directorStandings(request, env, H);
  if (path === "/api/scoring/analysis"  && method === "GET") return await matchAnalysis(request, env, H);

  // Squad read
  if (path === "/api/scoring/squad" && method === "GET") return await getSquad(request, env, H);

  // Public
  if (path === "/api/scoring/live" && method === "GET") return await publicLive(request, env, H);

  if (method === "POST") {
    let body;
    try { body = await request.json(); } catch { return H.fail("Malformed request."); }
    if (!body || typeof body !== "object") return H.fail("Malformed request.");

    try {
      if (path === "/api/scoring/discipline") return await saveDiscipline(request, env, H, body);
      if (path === "/api/scoring/stages")     return await saveStages(request, env, H, body);
      if (path === "/api/scoring/squads")     return await squadAction(request, env, H, body);
      if (path === "/api/scoring/entrants")   return await entrantAction(request, env, H, body);
      if (path === "/api/scoring/state")      return await setState(request, env, H, body);
      if (path === "/api/scoring/declare")    return await declarePlace(request, env, H, body);
      if (path === "/api/scoring/enter")      return await enterScore(request, env, H, body);
      if (path === "/api/scoring/publish")    return await publish(request, env, H, body);
      if (path === "/api/scoring/sync")       return await sync(request, env, H, body);
    } catch (err) {
      // Validation thrown from inside a loop reaches the scorer as a message;
      // anything else is a real fault and goes up to the Worker's handler.
      if (err instanceof RangeError) return H.fail(err.message);
      throw err;
    }
  }

  return null;   // not a scoring route
}

export const __test__ = { aggregate, buildStandings, sameHits, analyse, sameIdentity, normName, distinctNames };

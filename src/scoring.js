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

const asInt = v => {
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
            s.scorer_name,
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
      WHERE e.md_id = ? ORDER BY e.name`
  ).bind(md.id).all()).results || [];

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
      return {
        entrant_id: e.id, name: e.name, class: e.class,
        squad_id: e.squad_id, squad_name: e.squad_name,
        value: t.hits,
        display: `${t.hits}/${possible}`,
        recorded: t.recorded,
        complete: possible > 0 && t.recorded >= possible,
        per_stage: stages.map(s => ({ stage_id: s.id, ordinal: s.ordinal, hits: t.stages[s.id] ?? null }))
      };
    });
    rows.sort((a, b) => b.value - a.value);

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
      `SELECT s.id, s.ordinal, s.name, s.code, s.scorer_name,
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

async function directorStandings(request, env, H) {
  const url = new URL(request.url);
  const ev = await asDirector(env, url.searchParams.get("code"), H);
  if (!ev) return H.fail("That code isn't recognised.", 404);
  const md = await ownedDiscipline(env, ev.id, url.searchParams.get("md"));
  if (!md) return H.fail("That discipline isn't part of this event.", 404);

  const { rows, possible } = await buildStandings(env, md);
  return H.json({
    discipline: md.discipline, mode: md.mode, state: md.state,
    live_public: md.live_public, possible, standings: rows
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
    // direct entry: the ceiling depends on how the relays are combined
    const relays = md.relays || 1;
    if (md.aggregation === "sum")     return md.max_score * relays;
    if (md.aggregation === "bestn")   return md.max_score * Math.min(md.best_n || relays, relays);
    return md.max_score;              // best, or average, of single relays
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
                            sort_order, shooter_id, points, field_size, hits, available)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(ev.id, md.discipline, r.place, r.name, r.display, r.class,
           i + 1, shooterId, H.pointsForPlace(r.place), scored.length,
           hits, hits === null ? null : maxAvailable));
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

  const stages = md.mode === "stages"
    ? (await env.DB.prepare(
        "SELECT id, ordinal, name, shot_count FROM stages WHERE md_id = ? ORDER BY ordinal"
      ).bind(md.id).all()).results || []
    : [];

  const entrants = (await env.DB.prepare(
    "SELECT id, name, class FROM entrants WHERE squad_id = ? ORDER BY name"
  ).bind(sq.squad_id).all()).results || [];

  const ids = entrants.map(e => e.id);
  let cards = [], direct = [];

  if (ids.length) {
    const marks = ids.map(() => "?").join(",");
    if (md.mode === "stages") {
      cards = (await env.DB.prepare(
        `SELECT id, stage_id, entrant_id, hits, hit_count, recorded, version, scored_by, scored_at
           FROM score_cards WHERE entrant_id IN (${marks})`
      ).bind(...ids).all()).results || [];
    } else {
      direct = (await env.DB.prepare(
        `SELECT id, entrant_id, relay, score, x_count, version, scored_by, scored_at
           FROM direct_scores WHERE entrant_id IN (${marks})`
      ).bind(...ids).all()).results || [];
    }
  }

  return H.json({
    event: {
      name: sq.event_name, start_date: sq.start_date,
      venue: sq.venue, city: sq.city, state: sq.event_state
    },
    squad: { id: sq.squad_id, name: sq.squad_name, scorer_name: sq.scorer_name },
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
  const members = new Set(((await env.DB.prepare(
    "SELECT id FROM entrants WHERE squad_id = ?"
  ).bind(sq.squad_id).all()).results || []).map(r => r.id));

  const stageMap = new Map(((await env.DB.prepare(
    "SELECT id, shot_count FROM stages WHERE md_id = ?"
  ).bind(md.id).all()).results || []).map(r => [r.id, r.shot_count]));

  const accepted = [], conflicts = [], rejected = [];

  for (const item of items) {
    const entrantId = asInt(item.entrant_id);
    if (!members.has(entrantId)) {
      rejected.push({ id: item.id, reason: "That competitor isn't in this squad." });
      continue;
    }

    /* ---------- stage card ---------- */
    if (md.mode === "stages") {
      const stageId = asInt(item.stage_id);
      const shots = stageMap.get(stageId);
      if (!shots) { rejected.push({ id: item.id, reason: "Unknown stage." }); continue; }

      const hits = Array.isArray(item.hits) ? item.hits : null;
      if (!hits || hits.length !== shots) {
        rejected.push({ id: item.id, reason: `Stage needs exactly ${shots} shots.` });
        continue;
      }
      const norm = hits.map(v => (v === 1 || v === true) ? 1 : (v === 0 || v === false) ? 0 : null);
      const hitCount = norm.filter(v => v === 1).length;
      const recorded = norm.filter(v => v !== null).length;

      const existing = await env.DB.prepare(
        "SELECT * FROM score_cards WHERE stage_id = ? AND entrant_id = ?"
      ).bind(stageId, entrantId).first();

      if (!existing) {
        const id = String(item.id || crypto.randomUUID()).slice(0, 64);
        await env.DB.prepare(
          `INSERT INTO score_cards (id, md_id, stage_id, entrant_id, hits, hit_count,
                                    recorded, version, scored_by, squad_id, device_id)
           VALUES (?,?,?,?,?,?,?,1,?,?,?)`
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
              scored_by: existing.scored_by, scored_at: existing.scored_at
            }
          });
        }
        continue;
      }

      const nextVersion = existing.version + 1;
      await env.DB.prepare(
        `UPDATE score_cards SET hits=?, hit_count=?, recorded=?, version=?, scored_by=?,
                scored_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'), device_id=?
          WHERE id=? AND version=?`
      ).bind(JSON.stringify(norm), hitCount, recorded, nextVersion, scorer, device,
             existing.id, existing.version).run();
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
                                    version, scored_by, device_id)
         VALUES (?,?,?,?,?,?,1,?,?)`
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
            scored_by: existing.scored_by, scored_at: existing.scored_at
          }
        });
      }
      continue;
    }

    const nextVersion = existing.version + 1;
    await env.DB.prepare(
      `UPDATE direct_scores SET score=?, x_count=?, version=?, scored_by=?,
              scored_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'), device_id=?
        WHERE id=? AND version=?`
    ).bind(score, x, nextVersion, scorer, device, existing.id, existing.version).run();
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

export const __test__ = { aggregate, buildStandings, sameHits };

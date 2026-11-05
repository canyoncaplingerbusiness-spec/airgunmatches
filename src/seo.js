/**
 * Everything a search engine needs that JavaScript can't give it.
 *
 * The calendar is a single page that fetches its listings after load. That is
 * fine for a person and poor for a crawler: Google does run JavaScript, but as
 * a deferred second pass that is unreliable across a long tail of listings, and
 * a page whose source contains no event text has nothing to rank on the first
 * pass. Worse, a match that lives only as a fragment of one page has no address
 * of its own, so nothing can link to it, nothing can be shared, and Google's
 * event results — which require one event per URL — are out of reach entirely.
 *
 * This module fixes both without a framework or a build step. The Worker
 * already intercepts every request before the static files are served
 * (run_worker_first), so it can render an event page from the database, and
 * inject the listings into the calendar's own HTML on the way out.
 *
 * Nothing here changes what a visitor sees. The injected markup sits in the
 * container the client script writes to, so the moment that script runs it
 * replaces it with the interactive version.
 */

const esc = s => String(s == null ? "" : s)
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

/* JSON inside a <script> block has one way to go wrong: a string containing
   "</script>" ends the block early and the rest of the page becomes markup.
   Escaping the angle bracket costs nothing and closes it for good — a club is
   perfectly capable of naming a match something with a bracket in it. */
const jsonForScript = obj =>
  JSON.stringify(obj).replace(/</g, "\\u003c").replace(/\u2028|\u2029/g,
    m => m === "\u2028" ? "\\u2028" : "\\u2029");

const MONTHS = ["January", "February", "March", "April", "May", "June",
                "July", "August", "September", "October", "November", "December"];
const MO_ABBR = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export const STATE_NAMES = {
  AL:"Alabama",AK:"Alaska",AZ:"Arizona",AR:"Arkansas",CA:"California",CO:"Colorado",
  CT:"Connecticut",DE:"Delaware",FL:"Florida",GA:"Georgia",HI:"Hawaii",ID:"Idaho",
  IL:"Illinois",IN:"Indiana",IA:"Iowa",KS:"Kansas",KY:"Kentucky",LA:"Louisiana",
  ME:"Maine",MD:"Maryland",MA:"Massachusetts",MI:"Michigan",MN:"Minnesota",
  MS:"Mississippi",MO:"Missouri",MT:"Montana",NE:"Nebraska",NV:"Nevada",
  NH:"New Hampshire",NJ:"New Jersey",NM:"New Mexico",NY:"New York",
  NC:"North Carolina",ND:"North Dakota",OH:"Ohio",OK:"Oklahoma",OR:"Oregon",
  PA:"Pennsylvania",RI:"Rhode Island",SC:"South Carolina",SD:"South Dakota",
  TN:"Tennessee",TX:"Texas",UT:"Utah",VT:"Vermont",VA:"Virginia",WA:"Washington",
  WV:"West Virginia",WI:"Wisconsin",WY:"Wyoming",DC:"District of Columbia"
};

/* ------------------------------------------------------------------ */
/* URLs                                                                */
/* ------------------------------------------------------------------ */

export function slugify(s) {
  return String(s || "")
    .toLowerCase()
    .replace(/['’]/g, "")          // Sportsman's -> sportsmans, not sportsman-s
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 70)
    .replace(/-+$/, "");
}

/**
 * A readable address ending in the first eight characters of the id.
 *
 * The id has to be in there somewhere: two clubs can run a match of the same
 * name in the same month, and a slug alone would collide. Putting it at the end
 * keeps the readable part first, which is what a person scanning a search
 * result actually reads. Eight hex characters is four billion values against a
 * few hundred events — collision is not a practical concern, and the lookup
 * falls back to an exact match if one ever occurs.
 */
export function eventPath(ev) {
  const where = [ev.city, ev.state].filter(Boolean).join(" ");
  const slug = slugify(`${ev.name} ${where}`);
  const short = String(ev.id || "").replace(/-/g, "").slice(0, 8);
  return `/event/${slug ? slug + "-" : ""}${short}`;
}

/** Pulls the id fragment back out of a path built by eventPath. */
export function idFragmentFrom(path) {
  const m = String(path || "").match(/^\/event\/(?:.*?-)?([0-9a-fA-F]{8,36})\/?$/);
  return m ? m[1].toLowerCase() : null;
}

/* ------------------------------------------------------------------ */
/* Dates                                                               */
/* ------------------------------------------------------------------ */

const parts = d => String(d || "").slice(0, 10).split("-").map(Number);

export function longDate(d) {
  const [y, m, day] = parts(d);
  if (!y) return "";
  return `${MONTHS[m - 1]} ${day}, ${y}`;
}

export function dateRange(start, end) {
  if (!end || end === start) return longDate(start);
  const [sy, sm] = parts(start), [ey, em, ed] = parts(end);
  if (sy === ey && sm === em) {
    const [, , sd] = parts(start);
    return `${MONTHS[sm - 1]} ${sd}–${ed}, ${sy}`;
  }
  return `${longDate(start)} – ${longDate(end)}`;
}

/* ------------------------------------------------------------------ */
/* Structured data                                                     */
/* ------------------------------------------------------------------ */

/**
 * schema.org Event, as Google's event documentation asks for it.
 *
 * Only facts the database actually holds go in. Google's structured data
 * policy requires marked-up content to be visible on the page, and inventing a
 * price or a ticket URL to fill a recommended field is how a site earns a
 * manual action rather than a rich result.
 */
export function eventJsonLd(ev, origin) {
  const url = origin + eventPath(ev);
  const stateName = STATE_NAMES[ev.state] || ev.state;

  const data = {
    "@context": "https://schema.org",
    "@type": "Event",
    name: ev.name,
    startDate: ev.start_date,
    eventStatus: "https://schema.org/EventScheduled",
    eventAttendanceMode: "https://schema.org/OfflineEventAttendanceMode",
    url,
    location: {
      "@type": "Place",
      name: ev.venue,
      address: {
        "@type": "PostalAddress",
        addressLocality: ev.city,
        addressRegion: ev.state,
        addressCountry: "US"
      }
    }
  };

  if (ev.end_date && ev.end_date !== ev.start_date) data.endDate = ev.end_date;

  const disciplines = Array.isArray(ev.disciplines) ? ev.disciplines : [];
  const descr = (ev.note && ev.note.trim())
    || `${disciplines.join(", ") || "Shooting"} competition at ${ev.venue} in ` +
       `${ev.city}, ${stateName}.`;
  data.description = descr.slice(0, 500);

  if (ev.org) data.organizer = { "@type": "Organization", name: ev.org };
  if (ev.url) data.isAccessibleForFree = undefined;   // unknown; left unstated

  // A listing's own page is the best image we have. The logo is honest about
  // what the page is rather than pretending to be a photo of the match.
  data.image = [origin + "/img/logo-gun-lg.png"];

  return jsonForScript(data);
}

/** The calendar as an ItemList, so the homepage says what it is a list of. */
export function homeJsonLd(events, origin) {
  return jsonForScript({
    "@context": "https://schema.org",
    "@type": "ItemList",
    name: "Upcoming shooting matches",
    numberOfItems: events.length,
    itemListElement: events.slice(0, 100).map((ev, i) => ({
      "@type": "ListItem",
      position: i + 1,
      url: origin + eventPath(ev),
      name: ev.name
    }))
  });
}

/* ------------------------------------------------------------------ */
/* Server-rendered markup                                              */
/* ------------------------------------------------------------------ */

/**
 * The listings, as plain HTML, using the calendar's own class names so the
 * existing stylesheet renders them. Each one links to its own page, which is
 * how a crawler finds the event pages in the first place.
 */
export function listingsHtml(events) {
  if (!events.length) {
    return `<div class="empty"><strong>No events listed yet.</strong></div>`;
  }

  let html = "", lastKey = "";
  for (const ev of events) {
    const [y, m, d] = parts(ev.start_date);
    const key = `${y}-${m}`;
    if (key !== lastKey) {
      html += `<div class="monthhead">${MONTHS[m - 1]} ${y}</div>`;
      lastKey = key;
    }
    const multi = ev.end_date && ev.end_date !== ev.start_date;
    const [, em, ed] = parts(ev.end_date || ev.start_date);
    const tags = [
      ...(Array.isArray(ev.gun_types) ? ev.gun_types : []),
      ...(Array.isArray(ev.disciplines) ? ev.disciplines : [])
    ];

    html += `<article class="event">
      <div class="date">
        <span class="mo">${MO_ABBR[m - 1]}</span>
        <span class="dy">${d}</span>
        <span class="yr">${y}</span>
        ${multi ? `<span class="span">thru ${MO_ABBR[em - 1]} ${ed}</span>` : ""}
      </div>
      <div class="ebody">
        <h3><a href="${esc(eventPath(ev))}">${esc(ev.name)}</a></h3>
        <p class="meta">${esc(dateRange(ev.start_date, ev.end_date))}<span class="sep">|</span>${
          esc(ev.venue)} — ${esc(ev.city)}, ${esc(ev.state)}</p>
        <div class="tags">
          ${ev.live ? `<a class="tag live" href="${esc(eventPath(ev))}"><span class="dot"></span>LIVE NOW</a>` : ""}
          <span class="tag state">${esc(STATE_NAMES[ev.state] || ev.state)}</span>
          ${tags.map(t => `<span class="tag">${esc(t)}</span>`).join("")}
          ${ev.org ? `<span class="tag org">${esc(ev.org)}</span>` : ""}
        </div>
      </div>
    </article>`;
  }
  return html;
}

/**
 * An event while it is being shot.
 *
 * Everything that is true on any other day — the date, the venue, the town,
 * what it is shot with, the entry fee — is deliberately not here. Someone
 * opening this page during a match is not deciding whether to enter; they are
 * a competitor between lanes or somebody at home following a shooter, and the
 * only thing either of them wants is the current order. Driving directions to
 * a range they are standing in is noise.
 *
 * It comes back when the match closes, along with the final results.
 *
 * Standings arrive from the API rather than being baked in, because the page
 * refreshes itself every twenty seconds and a server-rendered table would be
 * stale the moment it was sent. The event's name and the fact that it is live
 * are rendered server-side so a crawler and a slow connection still get
 * something meaningful.
 */
export function liveEventPageHtml(ev, origin, sp = null) {
  const url = origin + eventPath(ev);
  const stateName = STATE_NAMES[ev.state] || ev.state;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LIVE — ${esc(ev.name)} | GunMatches.com</title>
<meta name="description" content="Live standings from ${esc(ev.name)}, updating as the match is scored.">
<link rel="canonical" href="${esc(url)}">
<link rel="icon" href="/img/icon-32.png" sizes="32x32">
<link rel="apple-touch-icon" href="/img/icon-180.png">
<meta property="og:title" content="LIVE — ${esc(ev.name)}">
<meta property="og:description" content="Live standings, updating as the match is scored.">
<meta property="og:url" content="${esc(url)}">
<style>
  :root{--navy:#121417;--navy-2:#1E2329;--amber:#B71D1C;--bg:#f5f6f8;--card:#fff;
    --line:#e2e6ec;--text:#1d2733;--muted:#677280;--green:#1f7a4d}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
    -webkit-font-smoothing:antialiased}
  .wrap{max-width:820px;margin:0 auto;padding:0 20px}
  header.site{background:linear-gradient(160deg,var(--navy),var(--navy-2));padding:14px 0}
  header.site .wrap{display:flex;align-items:center;gap:16px}
  header.site img{height:48px;width:auto;display:block}
  .livebar{background:var(--amber);color:#fff;padding:9px 0}
  .livebar .wrap{display:flex;align-items:center;gap:10px;font-weight:700;
    letter-spacing:.5px;font-size:13.5px;text-transform:uppercase}
  .dot{width:9px;height:9px;border-radius:50%;background:#fff;
    animation:pulse 1.6s ease-in-out infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
  h1{margin:22px 0 4px;font-size:25px;line-height:1.25;letter-spacing:-.3px}
  .sub{color:var(--muted);margin:0 0 18px;font-size:14.5px}
  .discbar{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 18px}
  .discbtn{background:#fff;border:1px solid var(--line);border-radius:999px;
    padding:8px 16px;font:inherit;font-size:14px;font-weight:600;cursor:pointer;color:var(--text)}
  .discbtn[aria-selected="true"]{background:var(--navy);border-color:var(--navy);color:#fff}
  .card{background:var(--card);border:1px solid var(--line);border-radius:10px;
    padding:0;margin:0 0 18px;overflow:hidden}
  .card h2{margin:0;padding:15px 18px;font-size:16.5px;border-bottom:1px solid var(--line);
    display:flex;align-items:center;gap:10px}
  .prog{font-size:12.5px;font-weight:400;color:var(--muted);margin-left:auto}
  table{width:100%;border-collapse:collapse;font-size:15px}
  th{text-align:left;padding:9px 18px;font-size:10.5px;text-transform:uppercase;
    letter-spacing:.6px;color:var(--muted);background:var(--bg)}
  td{padding:11px 18px;border-top:1px solid var(--line)}
  td.p{width:54px;font-weight:700;font-variant-numeric:tabular-nums}
  td.sc{text-align:right;font-weight:700;font-variant-numeric:tabular-nums;white-space:nowrap}
  .g1{color:#9a7b16}.g2{color:#6c7580}.g3{color:#8a5a33}
  .sq{color:var(--muted);font-size:13px}
  .shooting{color:var(--muted);font-weight:400;font-size:12px}
  .flag{display:inline-block;background:#eef1f5;color:#5b6570;border-radius:4px;
    padding:1px 6px;font-size:10.5px;font-weight:700;text-transform:uppercase;margin-left:6px}
  .foot{color:var(--muted);font-size:13px;text-align:center;padding:8px 0 40px}
  .foot a{color:var(--navy-2)}
  .empty{padding:30px 18px;text-align:center;color:var(--muted)}
  .spin{width:18px;height:18px;border:2px solid var(--line);border-top-color:var(--amber);
    border-radius:50%;display:inline-block;animation:sp .8s linear infinite;vertical-align:-4px}
  @keyframes sp{to{transform:rotate(360deg)}}
  ${sp ? sp.css : ""}
</style>
</head>
<body>

<header class="site">
  <div class="wrap">
    <a href="/"><img src="/img/logo-gun-lg.png" alt="GunMatches.com"
       width="381" height="352" style="height:48px;width:auto"></a>
  </div>
</header>

<div class="livebar"><div class="wrap"><span class="dot"></span>
  <span>Live — being scored now</span></div></div>
${sp ? sp.top : ""}

<div class="wrap">
  <h1>${esc(ev.name)}</h1>
  <p class="sub" id="sub">Standings update automatically. <span class="spin"></span></p>
  <div class="discbar" id="discbar"></div>
  <div id="board"><div class="card"><div class="empty">Loading standings…</div></div></div>
  ${sp ? sp.credit : ""}
</div>
${sp ? sp.rails : ""}

<p class="foot">
  <a href="/">Match calendar</a> · Full event details return when the match closes.
</p>

<script>
/* Poll rather than stream: a range has poor signal, a competitor's phone is in
   a pocket, and a dropped WebSocket that silently stops updating is worse than
   a table that is twenty seconds old and honest about it. */
const EVENT_ID = ${JSON.stringify(ev.id)};
let PICKED = null;

const esc = s => String(s == null ? "" : s)
  .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
  .replace(/"/g,"&quot;").replace(/'/g,"&#39;");

async function tick(){
  let data;
  try {
    const r = await fetch("/api/scoring/live?event=" + encodeURIComponent(EVENT_ID));
    if(!r.ok) throw new Error();
    data = await r.json();
  } catch {
    document.getElementById("sub").innerHTML =
      'Scores are not reachable just now, still trying. <span class="spin"></span>';
    return;
  }

  const discs = data.disciplines || [];
  if(!discs.length){
    document.getElementById("discbar").innerHTML = "";
    document.getElementById("board").innerHTML =
      '<div class="card"><div class="empty"><strong>No scores yet.</strong><br>' +
      'Standings appear here as the squads report in.</div></div>';
    return;
  }

  if(!PICKED || !discs.some(d => d.discipline === PICKED)) PICKED = discs[0].discipline;

  /* The filter only earns its place when there is more than one thing to
     filter. A single button that does nothing is just clutter on a phone. */
  document.getElementById("discbar").innerHTML = discs.length > 1
    ? discs.map(d => '<button class="discbtn" role="tab" data-d="' + esc(d.discipline) +
        '" aria-selected="' + (d.discipline === PICKED) + '">' + esc(d.discipline) + '</button>').join("")
    : "";

  const d = discs.find(x => x.discipline === PICKED);
  const rows = d.standings || [];
  const scored = rows.filter(r => r.place !== null).length;

  document.getElementById("board").innerHTML =
    '<div class="card"><h2>' + esc(d.discipline) +
      '<span class="prog">' + scored + ' of ' + rows.length + ' scored</span></h2>' +
    (rows.length
      ? '<table><tr><th>#</th><th>Competitor</th><th style="text-align:right">' +
        (d.mode === "stages" ? "Hits" : "Score") + '</th></tr>' +
        rows.map(r =>
          '<tr><td class="p ' + (r.place && r.place <= 3 ? "g" + r.place : "") + '">' +
            (r.place ?? "—") + '</td>' +
          '<td>' + esc(r.name) +
            (r.squad_name ? ' <span class="sq">· ' + esc(r.squad_name) + '</span>' : "") +
            (r.declared ? '<span class="flag">declared</span>' : "") + '</td>' +
          '<td class="sc">' + esc(r.display) +
            (r.complete === false ? ' <span class="shooting">shooting</span>' : "") +
          '</td></tr>').join("") +
        '</table>'
      : '<div class="empty">No competitors entered yet.</div>') +
    '</div>';

  const t = new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  document.getElementById("sub").textContent = "Updated " + t + " · refreshes automatically";
}

document.getElementById("discbar").addEventListener("click", e => {
  const b = e.target.closest("button[data-d]");
  if(!b) return;
  PICKED = b.dataset.d;
  tick();
});

tick();
setInterval(tick, 20000);
/* Catch up straight away when somebody comes back to the tab, rather than
   showing them whatever was on screen when they left. */
document.addEventListener("visibilitychange", () => { if(!document.hidden) tick(); });
</script>
</body>
</html>`;
}

/** One event, as its own page. */
export function eventPageHtml(ev, origin) {
  const url = origin + eventPath(ev);
  const stateName = STATE_NAMES[ev.state] || ev.state;
  const when = dateRange(ev.start_date, ev.end_date);
  const disciplines = Array.isArray(ev.disciplines) ? ev.disciplines : [];
  const gunTypes = Array.isArray(ev.gun_types) ? ev.gun_types : [];

  const metaDescr =
    `${when} at ${ev.venue}, ${ev.city}, ${stateName}. ` +
    (disciplines.length ? `${disciplines.join(", ")}. ` : "") +
    `Details and directions on GunMatches.com.`;

  const row = (label, value) => value
    ? `<div class="drow"><dt>${esc(label)}</dt><dd>${value}</dd></div>` : "";

  const results = ev.results && Object.keys(ev.results).length
    ? Object.entries(ev.results).map(([disc, rows]) => `
        <h2>${esc(disc)} results</h2>
        <table class="res">
          <thead><tr><th>Place</th><th>Competitor</th><th>Score</th><th>Class</th></tr></thead>
          <tbody>${rows.map(r => `<tr>
            <td class="p">${r.place ?? "—"}</td><td>${esc(r.competitor)}</td>
            <td>${esc(r.score || "")}</td><td>${esc(r.class || "")}</td></tr>`).join("")}
          </tbody>
        </table>`).join("")
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(ev.name)} — ${esc(when)} — ${esc(ev.city)}, ${esc(ev.state)} | GunMatches.com</title>
<meta name="description" content="${esc(metaDescr.slice(0, 300))}">
<link rel="canonical" href="${esc(url)}">
<link rel="icon" href="/img/icon-32.png" sizes="32x32">
<link rel="apple-touch-icon" href="/img/icon-180.png">
<meta property="og:type" content="website">
<meta property="og:title" content="${esc(ev.name)}">
<meta property="og:description" content="${esc(metaDescr.slice(0, 300))}">
<meta property="og:url" content="${esc(url)}">
<meta property="og:image" content="${esc(origin)}/img/logo-gun-lg.png">
<script type="application/ld+json">${eventJsonLd(ev, origin)}</script>
<style>
  :root{--navy:#121417;--navy-2:#1E2329;--amber:#B71D1C;--bg:#f5f6f8;--card:#fff;
    --line:#e2e6ec;--text:#1d2733;--muted:#677280}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
    -webkit-font-smoothing:antialiased}
  .wrap{max-width:780px;margin:0 auto;padding:0 20px}
  header.site{background:linear-gradient(160deg,var(--navy),var(--navy-2));padding:14px 0}
  header.site a{display:inline-flex;align-items:center;text-decoration:none}
  header.site img{height:60px;width:auto;display:block}
  .card{background:var(--card);border:1px solid var(--line);border-radius:10px;
    padding:26px;margin:24px 0;box-shadow:0 1px 2px rgba(18,38,63,.06)}
  h1{margin:0 0 6px;font-size:27px;line-height:1.25;letter-spacing:-.3px}
  .when{color:var(--amber);font-weight:700;font-size:17px;margin:0 0 20px}
  .tags{display:flex;flex-wrap:wrap;gap:7px;margin:0 0 22px}
  .tag{background:#f0f2f5;border:1px solid #e1e6ec;color:#4a5461;border-radius:999px;
    padding:4px 11px;font-size:12.5px;font-weight:600}
  dl{margin:0}
  .drow{display:flex;gap:16px;padding:11px 0;border-top:1px solid var(--line)}
  .drow dt{flex:0 0 132px;font-size:12.5px;font-weight:700;text-transform:uppercase;
    letter-spacing:.5px;color:var(--muted);padding-top:2px}
  .drow dd{margin:0;flex:1}
  .note{white-space:pre-wrap}
  a{color:var(--navy-2)}
  .btn{display:inline-block;background:var(--amber);color:#fff;font-weight:700;
    padding:12px 22px;border-radius:10px;text-decoration:none;margin-top:20px}
  h2{font-size:18px;margin:28px 0 10px}
  table.res{width:100%;border-collapse:collapse;font-size:14.5px}
  table.res th{text-align:left;padding:8px 10px;font-size:11px;text-transform:uppercase;
    letter-spacing:.6px;color:var(--muted);border-bottom:1px solid var(--line)}
  table.res td{padding:8px 10px;border-bottom:1px solid var(--line)}
  table.res td.p{width:56px;font-weight:700}
  footer.site{color:var(--muted);font-size:13.5px;text-align:center;padding:26px 0 40px}
  .crumb{font-size:13.5px;color:var(--muted);margin:18px 0 0}
</style>
</head>
<body>

<header class="site">
  <div class="wrap">
    <a href="/"><img src="/img/logo-gun-lg.png" alt="GunMatches.com"
       width="381" height="352" style="height:60px;width:auto"></a>
  </div>
</header>

<div class="wrap">
  <p class="crumb"><a href="/">Match calendar</a> ›
    <a href="/?state=${esc(ev.state)}">${esc(stateName)}</a></p>

  <div class="card">
    <h1>${esc(ev.name)}</h1>
    <p class="when">${esc(when)}</p>

    <div class="tags">
      <span class="tag">${esc(stateName)}</span>
      ${gunTypes.map(g => `<span class="tag">${esc(g)}</span>`).join("")}
      ${disciplines.map(d => `<span class="tag">${esc(d)}</span>`).join("")}
    </div>

    <dl>
      ${row("When", esc(when))}
      ${row("Venue", esc(ev.venue))}
      ${row("Where", `${esc(ev.city)}, ${esc(stateName)}`)}
      ${row("Disciplines", disciplines.map(esc).join(", "))}
      ${row("Shot with", gunTypes.map(esc).join(", "))}
      ${row("Organizer", ev.org ? esc(ev.org) : "")}
      ${row("Juniors", ev.juniors ? "Junior and youth shooters welcome" : "")}
      ${row("Details", ev.note ? `<span class="note">${esc(ev.note)}</span>` : "")}
    </dl>

    ${ev.url ? `<a class="btn" href="${esc(ev.url)}" rel="nofollow noopener"
         target="_blank">Registration and full details</a>` : ""}

    ${results}
  </div>

  <p class="crumb">Is this your match and something is wrong?
    Email <a href="mailto:Canyoncaplinger.business@gmail.com">Canyoncaplinger.business@gmail.com</a>
    and it is fixed the same day.</p>
</div>

<footer class="site">
  <a href="/">Every shooting match in the country, in date order</a>
</footer>
</body>
</html>`;
}

/* ------------------------------------------------------------------ */
/* Sitemap                                                             */
/* ------------------------------------------------------------------ */

export function sitemapXml(events, origin) {
  const urls = [
    { loc: origin + "/", priority: "1.0", changefreq: "daily" },
    { loc: origin + "/rankings.html", priority: "0.7", changefreq: "weekly" },
    { loc: origin + "/organizers.html", priority: "0.5", changefreq: "monthly" },
    ...events.map(ev => ({
      loc: origin + eventPath(ev),
      lastmod: (ev.results_updated_at || ev.created_at || "").slice(0, 10) || undefined,
      priority: "0.8",
      changefreq: "weekly"
    }))
  ];

  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map(u => `  <url>
    <loc>${esc(u.loc)}</loc>${u.lastmod ? `
    <lastmod>${esc(u.lastmod)}</lastmod>` : ""}
    <changefreq>${u.changefreq}</changefreq>
    <priority>${u.priority}</priority>
  </url>`).join("\n")}
</urlset>`;
}

/* ------------------------------------------------------------------ */
/* Injection into the existing calendar page                           */
/* ------------------------------------------------------------------ */

/**
 * Puts the rendered listings, a canonical link and the ItemList into the
 * calendar's own HTML.
 *
 * The listings go inside <div id="list">, replacing the loading spinner that
 * ships in the file. That container is the first thing the client script
 * overwrites, so a visitor with JavaScript sees the interactive calendar
 * exactly as before and never sees this markup at all.
 */
export function injectIntoCalendar(html, events, origin) {
  const canonical = `<link rel="canonical" href="${origin}/">`;
  const ld = `<script type="application/ld+json">${homeJsonLd(events, origin)}</script>`;

  let out = html;

  // Canonical + structured data, immediately before </head>
  out = out.replace("</head>", `${canonical}\n${ld}\n</head>`);

  // Listings, in place of the spinner
  out = out.replace(
    /<div id="list">[\s\S]*?<\/div>\s*<\/main>/,
    `<div id="list">${listingsHtml(events)}</div>\n</main>`
  );

  return out;
}

/** Canonical link for the other static pages, so the alias domain can't
 *  compete with the real one for the same content. */
export function injectCanonical(html, origin, path) {
  if (/rel=["']canonical["']/i.test(html)) return html;
  return html.replace("</head>", `<link rel="canonical" href="${origin}${path}">\n</head>`);
}

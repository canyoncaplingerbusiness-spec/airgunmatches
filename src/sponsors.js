/**
 * One sponsor, at the foot of the calendar.
 *
 * Why this is hand-rolled rather than an ad network: Google and Meta both
 * prohibit firearms content, so the usual tags are not available at any price.
 * The niche alternatives pay on volume this site does not have. Selling the
 * slot directly to a club, retailer or manufacturer is the only model that
 * works here — and it happens to be the better one, because it needs no
 * third-party JavaScript, follows nobody off the page, and keeps the calendar
 * as fast as it is now.
 *
 * The whole feature is: pick today's sponsor, draw a labelled strip, count
 * that it was seen, and count if it was clicked.
 */

const esc = s => String(s == null ? "" : s)
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

export const today = () => new Date().toISOString().slice(0, 10);

/**
 * The sponsor to show right now, or null.
 *
 * One slot is sold at a time, but the query tolerates overlapping bookings
 * rather than trusting that they never happen — the earliest-booked live
 * sponsor wins, so an accidental double-sale shows the one who bought first
 * instead of flickering between them from one page load to the next.
 */
export async function activeSponsor(env) {
  const d = today();
  return await env.DB.prepare(
    `SELECT id, name, image_url, image_mobile_url, badge_url, alt, tagline,
            dest_url, dest_url_alt, results_line,
            on_calendar, on_results, on_scoring
       FROM sponsors
      WHERE active = 1
        AND (starts_on IS NULL OR starts_on <= ?)
        AND (ends_on   IS NULL OR ends_on   >= ?)
      ORDER BY created_at ASC
      LIMIT 1`
  ).bind(d, d).first();
}

/**
 * Which tracked link to use, given the domain the visitor is actually on.
 *
 * Both domains serve the same calendar, so a sponsor cannot otherwise tell
 * whether a visit came from gunmatches.com or airgunmatches.com. They asked
 * for a link per site; this is where that choice is made, from the request's
 * own host rather than anything a page could claim.
 */
export function destFor(sponsor, host) {
  const alias = /(^|\.)airgunmatches\.com$/i.test(String(host || "").split(":")[0]);
  return (alias && sponsor.dest_url_alt) ? sponsor.dest_url_alt : sponsor.dest_url;
}

/**
 * Records that the strip was drawn.
 *
 * Upserted into a per-day row, so a sponsor running for a year costs 365 rows
 * rather than one per page view. Call it through ctx.waitUntil — a visitor
 * should never wait on a counter, and a failed write is worth losing rather
 * than showing anybody an error over.
 */
export async function countImpression(env, sponsorId) {
  await env.DB.prepare(
    `INSERT INTO sponsor_stats (sponsor_id, day, impressions, clicks)
     VALUES (?,?,1,0)
     ON CONFLICT(sponsor_id, day) DO UPDATE SET impressions = impressions + 1`
  ).bind(sponsorId, today()).run();
}

/**
 * Handles /s/<id> — count the click, then send the visitor on.
 *
 * The destination is read from the database by id and never taken from the
 * request. A redirector that forwards to whatever a query string names is an
 * open redirect: it lends this domain's good name to a phishing link, and it
 * is the single easiest way to turn a sponsor feature into a security
 * incident. There is no parameter here to abuse.
 */
export async function handleSponsorClick(env, id, securityHeaders, host) {
  const row = await env.DB.prepare(
    "SELECT id, dest_url, dest_url_alt FROM sponsors WHERE id = ? AND active = 1"
  ).bind(id).first();
  if (!row) return null;

  const dest = destFor(row, host);
  // Belt and braces: even a stored value has to be a plain web link.
  if (!dest || !/^https?:\/\//i.test(dest)) return null;

  await env.DB.prepare(
    `INSERT INTO sponsor_stats (sponsor_id, day, impressions, clicks)
     VALUES (?,?,0,1)
     ON CONFLICT(sponsor_id, day) DO UPDATE SET clicks = clicks + 1`
  ).bind(row.id, today()).run();

  /* The site's own referrer policy applies, deliberately. It sends the
     origin — gunmatches.com — but never the path, so the sponsor can see in
     their own analytics that the traffic came from here, which is exactly the
     evidence they want at renewal, while no visitor's reading is disclosed.
     Suppressing the referrer entirely would protect nothing extra and would
     make the traffic look like it came from nowhere. */
  return new Response(null, {
    status: 302,
    headers: {
      ...securityHeaders(),
      location: dest,
      "cache-control": "no-store"
    }
  });
}

/**
 * The strip itself.
 *
 * Labelled "Sponsor", plainly and before the name, because a paid placement
 * that reads as editorial is both dishonest and against the FTC's disclosure
 * guidance. rel="sponsored nofollow noopener" is the same statement made to
 * Google: this link was paid for and should pass no ranking credit.
 */
export function sponsorHtml(s) {
  /* The placement flag is checked here too, not only in the banner version.
     This is the fallback for a sponsor with no artwork, and without the check
     it cheerfully showed someone on the calendar who had not bought it. */
  if (!s || !s.on_calendar) return "";
  const inner = s.image_url
    ? `<img src="${esc(s.image_url)}" alt="${esc(s.alt || s.name)}" loading="lazy">`
    : `<span class="spname">${esc(s.name)}</span>`;

  return `<div class="sponsorstrip">
    <div class="wrap">
      <span class="splabel">Sponsor</span>
      <a class="splink" href="/s/${esc(s.id)}" rel="sponsored nofollow noopener"
         target="_blank">${inner}</a>
      ${s.tagline ? `<span class="sptag">${esc(s.tagline)}</span>` : ""}
      <a class="spabout" href="/organizers.html#sponsor">Sponsor this calendar</a>
    </div>
  </div>`;
}

/**
 * The calendar banner: a leaderboard on desktop, a smaller one on phones.
 *
 * <picture> rather than CSS, so the phone never downloads the wide artwork it
 * is not going to show. Width and height are stated so the page does not jump
 * as the image arrives — the banner sits above the footer, and a late reflow
 * there drags the whole page under the reader's thumb.
 */
export function calendarBannerHtml(s, host) {
  if (!s || !s.on_calendar || !s.image_url) return "";
  const alt = esc(s.alt || s.name);
  const img = s.image_mobile_url
    ? `<picture>
         <source media="(max-width:620px)" srcset="${esc(s.image_mobile_url)}">
         <img src="${esc(s.image_url)}" alt="${alt}" width="728" height="90" loading="lazy">
       </picture>`
    : `<img src="${esc(s.image_url)}" alt="${alt}" width="728" height="90" loading="lazy">`;

  return `<div class="sponsorstrip">
    <div class="wrap">
      <span class="splabel">Sponsor</span>
      <a class="splink" href="/s/${esc(s.id)}" rel="sponsored nofollow noopener"
         target="_blank">${img}</a>
    </div>
  </div>`;
}

/**
 * The line above published results, with the round badge.
 *
 * Shown only on an event that actually has results — a "results presented by"
 * credit on a page with no results reads as an advert wearing a hat.
 */
export function resultsCreditHtml(s, host) {
  if (!s || !s.on_results) return "";
  const line = s.results_line || `Match results presented by ${s.name}`;
  return `<div class="sponsorcredit">
    <span class="splabel">Sponsor</span>
    <a href="/s/${esc(s.id)}" rel="sponsored nofollow noopener" target="_blank">
      ${s.badge_url ? `<img src="${esc(s.badge_url)}" alt="${esc(s.alt || s.name)}"
           width="46" height="46" loading="lazy">` : ""}
      <span>${esc(line)}</span>
    </a>
  </div>`;
}

/**
 * The scoring screen logo.
 *
 * Deliberately the smallest placement on the site. A scorer is working a match
 * on a phone, often on poor signal, and the page has to stay usable offline —
 * so this is one lazy-loaded image in the header and nothing else. No banner,
 * no text, nothing that moves.
 */
export function scoringLogoHtml(s) {
  if (!s || !s.on_scoring || !s.image_url) return "";
  const src = s.badge_url || s.image_url;
  return `<a class="spscoring" href="/s/${esc(s.id)}" rel="sponsored nofollow noopener"
     target="_blank" title="Sponsor"><span>Sponsor</span><img src="${esc(src)}"
     alt="${esc(s.alt || s.name)}" height="22" loading="lazy"></a>`;
}

/** Styles, injected with the strip so the calendar's own file stays untouched. */
export const SPONSOR_CSS = `
  .sponsorstrip{background:#fff;border-top:1px solid #e2e6ec;
    border-bottom:1px solid #e2e6ec;padding:16px 0}
  .sponsorstrip .wrap{display:flex;align-items:center;gap:12px;flex-wrap:wrap;
    justify-content:center}
  .splabel{font-size:10px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;
    color:#8a94a0;border:1px solid #e2e6ec;border-radius:4px;padding:2px 6px;flex:none}
  .splink{display:inline-flex;align-items:center;text-decoration:none;flex:none;
    max-width:100%}
  .splink img{display:block;max-width:100%;height:auto}
  .sponsorcredit{display:flex;align-items:center;gap:10px;flex-wrap:wrap;
    border-top:1px solid #e2e6ec;margin-top:26px;padding-top:16px}
  .sponsorcredit a{display:inline-flex;align-items:center;gap:10px;text-decoration:none;
    color:#1d2733;font-weight:600;font-size:14.5px}
  .sponsorcredit img{border-radius:50%;display:block}
  .spscoring{display:inline-flex;align-items:center;gap:7px;text-decoration:none;flex:none}
  .spscoring span{font-size:9.5px;font-weight:700;letter-spacing:.7px;text-transform:uppercase;
    color:#8ea0b6}
  .spscoring img{display:block;height:22px;width:auto;opacity:.92}
`;

/**
 * Puts the strip just above the site footer, and its styles in the head.
 *
 * Returns the page unchanged when nothing is sold, so an unsold slot leaves no
 * empty box, no placeholder and no trace in the source.
 */
export function injectSponsor(html, sponsor, host) {
  const strip = calendarBannerHtml(sponsor, host) || sponsorHtml(sponsor);
  if (!sponsor || !strip) return html;
  return html
    .replace("</head>", `<style>${SPONSOR_CSS}</style>\n</head>`)
    .replace('<footer class="site">', `${strip}\n<footer class="site">`);
}

/** The scoring screen: logo into the header row, styles into the head. */
export function injectScoringSponsor(html, sponsor) {
  const logo = scoringLogoHtml(sponsor);
  if (!logo) return html;
  return html
    .replace("</head>", `<style>${SPONSOR_CSS}</style>\n</head>`)
    .replace('<span class="pill ok" id="pill" hidden>Saved</span>',
             `${logo}\n      <span class="pill ok" id="pill" hidden>Saved</span>`);
}

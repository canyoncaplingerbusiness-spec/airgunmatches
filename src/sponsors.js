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
    `SELECT id, name, image_url, alt, tagline, dest_url
       FROM sponsors
      WHERE active = 1
        AND (starts_on IS NULL OR starts_on <= ?)
        AND (ends_on   IS NULL OR ends_on   >= ?)
      ORDER BY created_at ASC
      LIMIT 1`
  ).bind(d, d).first();
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
export async function handleSponsorClick(env, id, securityHeaders) {
  const row = await env.DB.prepare(
    "SELECT id, dest_url FROM sponsors WHERE id = ? AND active = 1"
  ).bind(id).first();
  if (!row) return null;

  // Belt and braces: even a stored value has to be a plain web link.
  if (!/^https?:\/\//i.test(row.dest_url)) return null;

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
      location: row.dest_url,
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
  if (!s) return "";
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

/** Styles, injected with the strip so the calendar's own file stays untouched. */
export const SPONSOR_CSS = `
  .sponsorstrip{background:#fff;border-top:1px solid var(--line);
    border-bottom:1px solid var(--line);padding:14px 0}
  .sponsorstrip .wrap{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
  .splabel{font-size:10.5px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;
    color:#8a94a0;border:1px solid var(--line);border-radius:4px;padding:2px 6px;flex:none}
  .splink{display:inline-flex;align-items:center;text-decoration:none;flex:none}
  .splink img{max-height:46px;width:auto;display:block}
  .splink .spname{font-weight:700;font-size:17px;color:var(--navy)}
  .sptag{color:var(--muted);font-size:14px;flex:1;min-width:180px}
  .spabout{font-size:12.5px;color:var(--muted);text-decoration:underline;flex:none}
  @media (max-width:620px){ .sptag{display:none} }
`;

/**
 * Puts the strip just above the site footer, and its styles in the head.
 *
 * Returns the page unchanged when nothing is sold, so an unsold slot leaves no
 * empty box, no placeholder and no trace in the source.
 */
export function injectSponsor(html, sponsor) {
  if (!sponsor) return html;
  return html
    .replace("</head>", `<style>${SPONSOR_CSS}</style>\n</head>`)
    .replace('<footer class="site">', `${sponsorHtml(sponsor)}\n<footer class="site">`);
}

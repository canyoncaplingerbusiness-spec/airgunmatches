/**
 * AirgunMatches.com — service worker
 *
 * Its only job is to make /score.html open when a phone has no signal.
 *
 * It is deliberately as narrow as a service worker can be. A worker registered
 * at the site root sees every request the browser makes, so the rule here is
 * that anything which isn't the scoring page is left completely alone — the
 * handler returns without calling respondWith, and the browser behaves exactly
 * as if no service worker existed.
 *
 * That matters more than it sounds. A cache-first worker over the whole site
 * would serve stale calendar pages, and caching an API response would mean a
 * scorer or an admin acting on data that is quietly out of date. Neither is
 * worth the convenience.
 */

const CACHE = "agm-score-v1";
const PAGE = "/score.html";

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE).then(c => c.add(PAGE)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", event => {
  const req = event.request;
  if (req.method !== "GET") return;

  let url;
  try { url = new URL(req.url); } catch { return; }
  if (url.origin !== self.location.origin) return;

  // Everything except the scoring page is none of this worker's business.
  const wanted = url.pathname === PAGE ||
    (req.mode === "navigate" && url.pathname === PAGE);
  if (!wanted) return;

  /* Network first, so a scorer who has signal always gets the current page and
     a fix deployed mid-match reaches them. The cache is the fallback, not the
     default — it only answers when the network doesn't. */
  event.respondWith(
    fetch(req)
      .then(res => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(PAGE, copy)).catch(() => {});
        }
        return res;
      })
      .catch(() => caches.match(PAGE).then(hit => hit || Response.error()))
  );
});

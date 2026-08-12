# GunMatches.com — Architecture & Operations

Everything you need to run, change, back up and roll back the site.

**Live at https://gunmatches.com.** airgunmatches.com redirects to it.

---

## What the site does

Four things, each usable without an account:

1. **A national calendar** of shooting matches, filterable by state, what it's shot
   with, and discipline. Organizers submit; you approve by hand.
2. **Live scoring** — a match director sets out stages and squads, hands each squad's
   scorer a code, and they score from their phone. Works with no signal.
3. **Results** — either posted live from the scoring above, or pasted in from a
   spreadsheet after a paper match.
4. **National rankings** built from posted results, scored on finishing place.

---

## Architecture

```
Visitor
   │
   ▼
Cloudflare edge  ──  DNS + TLS + caching
   │
   ▼
Worker "airgunmatches"          ← serves the pages AND the API
   ├── /                        calendar              (public/index.html)
   ├── /organizers.html         organizer hub         (public/organizers.html)
   ├── /match.html              director console      (public/match.html)
   ├── /score.html              squad scoring         (public/score.html)
   ├── /results.html            paste-in results      (public/results.html)
   ├── /rankings.html           national standings    (public/rankings.html)
   ├── /admin.html              your review dashboard (public/admin.html)
   ├── /sw.js                   service worker, scoring page only
   └── /api/*                   JSON API              (src/index.js, src/scoring.js)
             │
             ▼
   D1 database "airgunmatches-db"
```

One Worker serves the pages and the API, so a rollback restores both together. The
browser never touches the database.

**Names you'll need**

| Thing | Name / ID |
|---|---|
| Cloudflare account | `c49eb10e09b5c86f3338c581982a80cb` |
| Worker | `airgunmatches` (the name predates the rename; harmless) |
| D1 database | `airgunmatches-db` |
| D1 database ID | `986bbc6c-b6de-4798-8305-1ee55e2df957` |
| gunmatches.com zone ID | `b09d8d54a19f41ff7abf0eeac634cc86` |
| GitHub repo | `canyoncaplingerbusiness-spec/airgunmatches` |
| Fallback URL | `airgunmatches.canyoncaplinger-business.workers.dev` |
| Contact address | Canyoncaplinger.business@gmail.com |

The Worker, repo and database are all still named "airgunmatches". Renaming them
would mean recreating the Worker and re-pointing four custom domains, for no
functional gain. It costs nothing to leave them.

---

## The two domains

**gunmatches.com** is the site. **airgunmatches.com** 301-redirects to it, and the
front page lands on `?gun=Airgun` so anyone typing the old address sees airgun
matches with the filter already applied.

The redirect is controlled by a single Worker variable:

| `REDIRECT_HOST` | Effect |
|---|---|
| `gunmatches.com` | airgunmatches.com redirects. **Current setting.** |
| *(empty)* | Both domains serve the site normally. |

**To undo the move:** Workers → airgunmatches → Settings → Variables → clear
`REDIRECT_HOST` → Deploy. Seconds, no code change, no deploy from GitHub.

Three things are deliberately never redirected: anything that isn't GET or HEAD (a
301 turns a POST into a GET and would silently discard an organizer's submission),
`/api/`, and the workers.dev address.

**Custom domains on the Worker:** gunmatches.com, www.gunmatches.com,
airgunmatches.com, www.airgunmatches.com.

---

## Recurring cost

| Service | Plan | Cost |
|---|---|---|
| Cloudflare Workers | Free — 100,000 requests/day | $0 |
| Cloudflare D1 | Free — 5 GB, 5M row reads/day | $0 |
| Cloudflare DNS + Universal SSL, both zones | Free | $0 |
| Turnstile | Free | $0 |
| Domains (Porkbun) | two | ~$22/year |
| **Total** | | **$0/month** |

No paid Cloudflare product is enabled. Set a billing alert under Manage account →
Billing → Notifications; nothing should ever bill, so any alert means something
changed.

---

## Secrets and settings

Cloudflare → Workers → airgunmatches → Settings → Variables and secrets.

| Name | Type | Purpose |
|---|---|---|
| `ADMIN_PASSWORD` | Secret | Your dashboard passphrase |
| `TURNSTILE_SECRET_KEY` | Secret | Server-side spam verification |
| `IP_SALT` | Secret | Salts the hashing of submitter IP addresses |
| `REDIRECT_HOST` | Text | The domain switch, above |

---

## Data model

Beyond `events`, `results` and `shooters`, live scoring adds:

| Table | Holds |
|---|---|
| `match_disciplines` | One row per discipline per event: scoring mode, state, settings |
| `stages` | Stage list for a stage-scored discipline, each with its own shot count |
| `squads` | Squads and their codes |
| `entrants` | The roster, optionally linked to a squad and a shooter |
| `score_cards` | One card per competitor per stage, with a version number |
| `direct_scores` | One row per competitor per relay, for bench rest and similar |
| `score_history` | Append-only. Every change, who made it, when |
| `declared_places` | Placings you set by hand, kept separate from computed ones |
| `scoring_rate` | Rate limiting per squad code |

`schema.sql` and `schema-scoring.sql` are the reference copies. Both are already
applied — they exist so the database could be rebuilt from nothing.

**Gun types are a fixed list**, defined identically in three places: `src/index.js`,
`public/index.html`, `public/admin.html`. A test compares all three; if you add a
type, add it everywhere. Disciplines, by contrast, accept write-ins — that's what
keeps the discipline filter useful.

---

## Deploying a change

The repository is the source of truth. Any commit to `main` triggers a rebuild,
roughly 30 seconds.

1. Edit files at `github.com/canyoncaplingerbusiness-spec/airgunmatches`
   (or edit locally and drag `public` and `src` onto **Add file → Upload files**)
2. Commit
3. Cloudflare rebuilds automatically

**Drag the `public` and `src` folders themselves**, never the parent folder — that
would nest everything a level deep and break the site.

**Changed files sit behind the cache.** New files appear instantly; edited ones may
serve stale for a while. Hard-refresh (`Ctrl`+`Shift`+`R`), or Caching →
Configuration → Purge Everything.

| File | Purpose |
|---|---|
| `public/index.html` | Calendar and submission form |
| `public/organizers.html` | Organizer hub — the front door for match directors |
| `public/match.html` | Director console: stages, squads, codes, standings |
| `public/score.html` | Squad scoring, offline-capable |
| `public/sw.js` | Service worker. Caches the scoring page **only** |
| `public/results.html` | Paste-in results |
| `public/rankings.html` | National standings |
| `public/admin.html` | Your review dashboard |
| `src/index.js` | Worker: API, auth, validation, the redirect switch |
| `src/scoring.js` | Live scoring API and its access rules |
| `wrangler.jsonc` | Configuration, D1 binding, `REDIRECT_HOST` |

---

## Rolling back

**A bad deploy** — Workers → airgunmatches → Deployments → last good one →
**Rollback**. Restores code and pages together.

**The domain move** — clear `REDIRECT_HOST`, as above.

**Something much worse** — the Netlify project still exists at
`airgunmatches.netlify.app`, reading from Supabase, showing data as it was at
migration. Emergency fallback only, not a live mirror. Don't delete it or the
Supabase project without deciding you'll never want them.

**One caution about `sw.js`:** a service worker stays registered in a visitor's
browser even after a rollback removes the file. It's deliberately narrow — it only
handles `/score.html`, network-first, and passes everything else straight through —
but it's the one thing here that leaves a trace on other people's machines.

---

## Reviewing submissions

**https://gunmatches.com/admin.html**, sign in with `ADMIN_PASSWORD`. Sessions last
12 hours.

Tabs: **Pending / Approved / Denied / All**, each with a live count.

| Button | Effect |
|---|---|
| ✓ Approve | Live on the calendar immediately, and issues the event's results code |
| ✕ Deny | Never appears publicly; kept on record |
| Edit | Full inline form, including gun types and disciplines |
| Move back to pending | Undo a decision |
| Remove from calendar | Un-publish something approved |
| Delete permanently | Gone for good; asks first. See below |

**What "delete permanently" actually removes.** Everything belonging to that event:
its results, disciplines, stages, squads, roster, score cards, declared winners,
and the audit trail of who entered each score. Most of that happens through the
database's own cascade rules; the audit trail is removed explicitly, because it
deliberately has no foreign key and would otherwise survive as unreachable rows
holding scorers' names.

**Rankings correct themselves immediately.** They are computed from the results
table on every page load, never stored, so a deleted event's points simply stop
counting. Nothing to rebuild.

**Competitors' identities are kept.** A shooter is a person, not a score — delete
one of Dale Whitcomb's five matches and he keeps the other four.

Prefer **Deny** over **Delete** for spam — denied rows cost nothing and stop you
reviewing the same junk twice.

**Check the gun type on every submission.** It's the field organizers are most
likely to get wrong, and a match filed under the wrong one is invisible to the
people looking for it.

---

## Running a match — the short version

For you, so you can answer questions. The long version is on `/organizers.html`.

1. Director opens `/match.html` with the **event code** — the same one used for
   results upload, issued on approval.
2. Per discipline they choose **stage scoring** (field target, precision rifle,
   silhouette) or **direct entry** (bench rest and anything graded off the target).
3. Stage scoring: stages, each with its own shot count. Direct entry: score type,
   which direction wins, relays, and how relays combine.
4. Squads are created; **each gets its own code**. Codes can be reissued
   individually — a lost phone revokes one squad's code and leaves the rest working.
5. The match is opened. Scorers can now enter scores, and not before.
6. Standings build as scores arrive. Ties are left as ties; the director ticks a
   winner and everyone below moves down.
7. Publish sends the results to the event's page and the national rankings.

**Three codes, three different jobs:**

| Who | Key | Can do |
|---|---|---|
| You | `ADMIN_PASSWORD` | everything |
| Match director | the event's results code | set up and run their own match |
| Squad scorer | a per-squad code | score **that squad only** |

A squad code cannot read the director view, change the match, publish, or reach
another squad — enforced on the server, not just hidden in the interface.

---

## Backups

**From the dashboard** — **Backup JSON** and **Backup CSV** in the header. Both
include submitter details. Do this monthly and before any bulk change.

**Restoring** — the JSON contains complete rows with original IDs. Ask Claude to
restore from it, or use Cloudflare → D1 → airgunmatches-db → Console.

Cloudflare keeps its own point-in-time recovery for D1, but your own copy is the one
you control.

---

## Security

- The browser never reaches the database. The Worker is the only path.
- Public reads select a fixed column list that excludes submitter names, emails and
  every review field — they cannot leak, because they are never selected.
- Submissions are forced to `pending`. A client cannot set status or any review field.
- Admin routes require a signed session cookie: HttpOnly, Secure, SameSite=Strict,
  12-hour expiry. Password comparison is constant-time.
- Ten failed logins from one address in fifteen minutes locks it out.
- Turnstile, plus a honeypot, plus server-side validation on every submission.
- Submitter IPs are stored only as salted hashes, never raw.
- Squad codes are scoped on the server on every request: the competitor must be in
  that squad, the stage must belong to that discipline, the match must be open.
- Every score is attributed and appended to `score_history`, which is never updated
  or deleted.
- Two scorers editing the same card is detected by version number. The second is
  shown both copies and chooses. Nothing is silently overwritten.
- Scoring writes are rate-limited per squad code.
- Security headers on every response.

---

## Testing

Four suites, run in a sandbox against the real code:

| Suite | Covers |
|---|---|
| Schema constraints | Every CHECK and UNIQUE in the scoring schema |
| Scoring API | Squad scoping, conflicts, standings, aggregation, publishing |
| Scoring page | Offline queue, persistence, conflict resolution, direct entry |
| End-to-end | The real page against the real API and a real database |

They exist to be re-run when something changes. Ask Claude to run them before any
deploy that touches scoring — several real bugs were caught this way, including one
where a fresh phone never showed the scoring screen at all.

---

## Known gaps

- Rankings have not been verified against a large realistic dataset.
- Every event is currently tagged **Airgun**. Rimfire, Centerfire and Shotgun won't
  appear in the Type filter until an event uses them — the filter only offers types
  that have events behind them.
- One event publishes a match director's contact email in its description
  (`jeff-cloud@utexas.edu`, Arlington Sportsman's Club). Deliberate, but worth
  knowing it's on a public page.

---

## Turnstile — read this before adding a domain

The spam check has exactly one failure mode visible to an organizer: **"Spam check
failed. Please reload the page and try again."** Three completely different causes
produce that identical message, which is what made it hard to diagnose the first
time. The Worker now logs which one it is — see below.

### A new domain must be added to the widget

**This is the one that will catch you out.** The Turnstile widget holds a list of
hostnames it will accept, and it rejects a token from anywhere else. Adding a domain
to Cloudflare and attaching it to the Worker is *not* enough — the widget doesn't
know about it, and every submission from that domain fails silently.

Turnstile → widget `airgunmatches-submissions` → **Edit Widget** → Hostname
Management. Currently 5 of 10 used:

```
gunmatches.com
www.gunmatches.com
airgunmatches.com
www.airgunmatches.com
airgunmatches.canyoncaplinger-business.workers.dev
```

Add any new domain here at the same time you attach it to the Worker.

### Rotating the secret key

Do both halves back to back. The old secret stops working the moment you rotate,
and until the Worker has the new one every submission fails.

1. Turnstile → widget → **Widget Keys** → copy the **Secret Key**.
2. Immediately: Workers → airgunmatches → Settings → Variables and secrets →
   `TURNSTILE_SECRET_KEY` → paste over the value → **Deploy**.
3. Submit a test event through the form, then delete it from the dashboard.

**Copy the secret key, not the site key.** They sit next to each other, both begin
`0x4AAAAAAA…`, and pasting the wrong one is silent. The site key is 24 characters;
the secret is around 35. If what you pasted looks the same length as the site key,
it's the wrong one. This exact mistake cost an hour once already.

The site key is public and lives in `index.html`. It never changes and never needs to.

### When it fails, read the log

`turnstileOk` in `src/index.js` logs the reason to Workers → Observability. It never
logs the secret itself — only its length, which is enough to spot a truncated paste
or the wrong key.

| Logged code | Means |
|---|---|
| `invalid-input-secret` | The secret in the Worker is wrong |
| `timeout-or-duplicate` | The token was already used or went stale — reload the form |
| `invalid-input-response` | The token is malformed |
| hostname in the payload | The widget doesn't allow that hostname |

Don't guess at this. One test submission plus one log line identifies it exactly.

-- ============================================================
-- AirgunMatches.com — Cloudflare D1 schema
--
-- Ported from the Supabase Postgres schema. D1 is SQLite, so:
--   * arrays become JSON text (disciplines)
--   * booleans become integers (0/1)
--   * timestamps become ISO-8601 text
--   * CHECK constraints replace what row-level security did
--
-- Security note: SQLite has no row-level security and no column
-- privileges. Everything that RLS enforced in Postgres is now
-- enforced by the Worker API — the browser never reaches D1
-- directly, so the API is the only door.
-- ============================================================

DROP TABLE IF EXISTS events;

CREATE TABLE events (
  id               TEXT PRIMARY KEY,           -- UUID, preserved from Supabase on import
  name             TEXT NOT NULL,
  start_date       TEXT NOT NULL,              -- 'YYYY-MM-DD'
  end_date         TEXT,                       -- NULL for single-day events
  venue            TEXT NOT NULL,
  city             TEXT NOT NULL,
  state            TEXT NOT NULL,              -- two-letter code
  disciplines      TEXT NOT NULL,              -- JSON array, e.g. '["Bench Rest","Long Range"]'
  org              TEXT,
  juniors          INTEGER NOT NULL DEFAULT 0, -- 0 / 1
  url              TEXT,
  video_url        TEXT,
  note             TEXT,

  -- Private. Never returned by any public endpoint.
  submitter_name   TEXT NOT NULL,
  submitter_email  TEXT NOT NULL,

  -- Review workflow
  status           TEXT NOT NULL DEFAULT 'pending',
  created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  reviewed_at      TEXT,
  reviewed_by      TEXT,                       -- Cloudflare Access email of the reviewer
  review_note      TEXT,

  -- Spam / abuse forensics. Never returned publicly.
  submit_ip_hash   TEXT,                       -- salted hash, not the raw address
  submit_country   TEXT,

  CHECK (status IN ('pending','approved','denied')),
  CHECK (length(trim(name))   BETWEEN 3 AND 160),
  CHECK (length(trim(venue))  BETWEEN 2 AND 160),
  CHECK (length(trim(city))   BETWEEN 2 AND 100),
  CHECK (length(state) = 2 AND state = upper(state)),
  CHECK (start_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
  CHECK (end_date IS NULL OR
         (end_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]' AND end_date >= start_date)),
  CHECK (start_date BETWEEN '2015-01-01' AND '2100-01-01'),
  CHECK (juniors IN (0,1)),
  CHECK (org IS NULL OR length(org) <= 120),
  CHECK (note IS NULL OR length(note) <= 1000),
  CHECK (url IS NULL OR url LIKE 'http://%' OR url LIKE 'https://%'),
  -- Only YouTube links may be embedded; anything else is rejected outright.
  CHECK (video_url IS NULL OR
         video_url LIKE 'https://www.youtube.com/%'  OR
         video_url LIKE 'https://youtube.com/%'      OR
         video_url LIKE 'https://m.youtube.com/%'    OR
         video_url LIKE 'https://youtu.be/%'),
  CHECK (length(trim(submitter_name)) BETWEEN 2 AND 120),
  CHECK (submitter_email LIKE '%_@_%._%' AND length(submitter_email) <= 200),
  -- disciplines must be a non-empty JSON array of at most 8 entries
  CHECK (json_valid(disciplines)
         AND json_type(disciplines) = 'array'
         AND json_array_length(disciplines) BETWEEN 1 AND 8)
);

-- ---------- Indexes ----------
-- Public calendar: approved events in date order (the hot path)
CREATE INDEX idx_events_status_start   ON events(status, start_date);
-- Admin dashboard: newest submissions first
CREATE INDEX idx_events_created        ON events(created_at DESC);
-- State filter over approved events only
CREATE INDEX idx_events_state          ON events(state) WHERE status = 'approved';
-- Duplicate detection on submit
CREATE INDEX idx_events_dupe           ON events(lower(name), start_date, state);
-- Rate-limit lookups by submitter
CREATE INDEX idx_events_ip             ON events(submit_ip_hash, created_at);

-- ---------- Duplicate protection ----------
-- The same match, on the same day, at the same venue, cannot be listed twice.
-- Case- and whitespace-insensitive so "PSA Field Target" and "psa field target "
-- collide as intended.
CREATE UNIQUE INDEX idx_events_unique_match
  ON events(lower(trim(name)), start_date, lower(trim(venue)));

-- ---------- Review stamping ----------
-- Mirrors the Postgres trigger: records when and by whom a status changed,
-- and prevents created_at from being rewritten by an update.
CREATE TRIGGER trg_events_stamp_review
AFTER UPDATE OF status ON events
FOR EACH ROW
WHEN NEW.status IS NOT OLD.status
BEGIN
  UPDATE events
     SET reviewed_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
   WHERE id = NEW.id;
END;

CREATE TRIGGER trg_events_freeze_created
AFTER UPDATE OF created_at ON events
FOR EACH ROW
WHEN NEW.created_at IS NOT OLD.created_at
BEGIN
  UPDATE events SET created_at = OLD.created_at WHERE id = NEW.id;
END;

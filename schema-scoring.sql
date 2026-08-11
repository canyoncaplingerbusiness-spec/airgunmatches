-- ============================================================
-- Live match scoring — schema additions
-- Applied to D1 "airgunmatches-db". Kept here for reference and
-- for rebuilding the database from scratch if ever needed.
-- ============================================================

CREATE TABLE IF NOT EXISTS match_disciplines (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id      TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  discipline    TEXT NOT NULL,
  mode          TEXT NOT NULL,
  state         TEXT NOT NULL DEFAULT 'setup',
  live_public   INTEGER NOT NULL DEFAULT 0,
  score_type    TEXT,
  winner        TEXT DEFAULT 'highest',
  decimals      INTEGER NOT NULL DEFAULT 0,
  max_score     INTEGER,
  shots_fired   INTEGER,
  relays        INTEGER NOT NULL DEFAULT 1,
  aggregation   TEXT NOT NULL DEFAULT 'sum',
  best_n        INTEGER,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  UNIQUE (event_id, discipline),
  CHECK (mode IN ('stages','direct')),
  CHECK (state IN ('setup','live','complete')),
  CHECK (live_public IN (0,1)),
  CHECK (score_type IS NULL OR score_type IN ('points','group','time')),
  CHECK (winner IN ('highest','lowest')),
  CHECK (decimals BETWEEN 0 AND 4),
  CHECK (relays BETWEEN 1 AND 20),
  CHECK (aggregation IN ('sum','best','average','bestn')),
  CHECK (aggregation <> 'bestn' OR (best_n IS NOT NULL AND best_n BETWEEN 1 AND relays))
);

CREATE TABLE IF NOT EXISTS stages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  md_id INTEGER NOT NULL REFERENCES match_disciplines(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL, name TEXT NOT NULL, shot_count INTEGER NOT NULL,
  UNIQUE (md_id, ordinal),
  CHECK (shot_count BETWEEN 1 AND 100),
  CHECK (length(trim(name)) BETWEEN 1 AND 60)
);

CREATE TABLE IF NOT EXISTS squads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  md_id INTEGER NOT NULL REFERENCES match_disciplines(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL, name TEXT NOT NULL, code TEXT NOT NULL, scorer_name TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  UNIQUE (md_id, ordinal),
  CHECK (length(trim(name)) BETWEEN 1 AND 60)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_squads_code ON squads(code);

CREATE TABLE IF NOT EXISTS entrants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  md_id INTEGER NOT NULL REFERENCES match_disciplines(id) ON DELETE CASCADE,
  squad_id INTEGER REFERENCES squads(id) ON DELETE SET NULL,
  shooter_id INTEGER REFERENCES shooters(id) ON DELETE SET NULL,
  name TEXT NOT NULL, class TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  CHECK (length(trim(name)) BETWEEN 1 AND 120)
);
CREATE INDEX IF NOT EXISTS idx_entrants_md ON entrants(md_id);
CREATE INDEX IF NOT EXISTS idx_entrants_squad ON entrants(squad_id);

CREATE TABLE IF NOT EXISTS score_cards (
  id TEXT PRIMARY KEY,
  md_id INTEGER NOT NULL REFERENCES match_disciplines(id) ON DELETE CASCADE,
  stage_id INTEGER NOT NULL REFERENCES stages(id) ON DELETE CASCADE,
  entrant_id INTEGER NOT NULL REFERENCES entrants(id) ON DELETE CASCADE,
  hits TEXT NOT NULL, hit_count INTEGER NOT NULL DEFAULT 0,
  recorded INTEGER NOT NULL DEFAULT 0, version INTEGER NOT NULL DEFAULT 1,
  scored_by TEXT,
  scored_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  squad_id INTEGER REFERENCES squads(id) ON DELETE SET NULL, device_id TEXT,
  UNIQUE (stage_id, entrant_id),
  CHECK (json_valid(hits) AND json_type(hits) = 'array'),
  CHECK (version >= 1)
);
CREATE INDEX IF NOT EXISTS idx_cards_md ON score_cards(md_id);
CREATE INDEX IF NOT EXISTS idx_cards_entrant ON score_cards(entrant_id);
CREATE INDEX IF NOT EXISTS idx_cards_squad ON score_cards(squad_id);

CREATE TABLE IF NOT EXISTS direct_scores (
  id TEXT PRIMARY KEY,
  md_id INTEGER NOT NULL REFERENCES match_disciplines(id) ON DELETE CASCADE,
  entrant_id INTEGER NOT NULL REFERENCES entrants(id) ON DELETE CASCADE,
  relay INTEGER NOT NULL DEFAULT 1, score REAL, x_count INTEGER,
  version INTEGER NOT NULL DEFAULT 1, scored_by TEXT,
  scored_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  device_id TEXT,
  UNIQUE (entrant_id, relay),
  CHECK (relay BETWEEN 1 AND 20),
  CHECK (x_count IS NULL OR x_count >= 0),
  CHECK (version >= 1)
);
CREATE INDEX IF NOT EXISTS idx_direct_md ON direct_scores(md_id);

CREATE TABLE IF NOT EXISTS score_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL, ref_id TEXT NOT NULL, md_id INTEGER NOT NULL,
  version INTEGER NOT NULL, payload TEXT NOT NULL,
  actor_name TEXT, via_code TEXT, device_id TEXT,
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  CHECK (kind IN ('card','direct'))
);
CREATE INDEX IF NOT EXISTS idx_history_ref ON score_history(ref_id, version);
CREATE INDEX IF NOT EXISTS idx_history_md ON score_history(md_id, at);

CREATE TABLE IF NOT EXISTS declared_places (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  md_id INTEGER NOT NULL REFERENCES match_disciplines(id) ON DELETE CASCADE,
  entrant_id INTEGER NOT NULL REFERENCES entrants(id) ON DELETE CASCADE,
  place INTEGER NOT NULL, declared_by TEXT,
  declared_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  UNIQUE (md_id, entrant_id),
  CHECK (place >= 1)
);

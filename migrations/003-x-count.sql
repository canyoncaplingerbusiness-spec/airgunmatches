-- Records X count on every published result.
--
-- Bench rest scores are written "248-6X": the points, then how many of those
-- shots landed inside the X ring. The X count has always been visible inside
-- the score text, but never as a number the database could sort on, so two
-- shooters level on points fell back to alphabetical order — which is not how
-- any bench rest match in the country is decided.
--
-- Nullable on purpose. Field target, PRS and silhouette have no X ring, and a
-- zero there would read as "shot at the X and missed every time" rather than
-- "this discipline does not have one".
--
-- Safe to re-run: SQLite errors on a duplicate column, so check first with
--   SELECT name FROM pragma_table_info('results') WHERE name = 'x_count';

ALTER TABLE results ADD COLUMN x_count INTEGER;

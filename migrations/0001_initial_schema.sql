-- Current local-first MVP persists one atomic snapshot. Domain tables and AGE/pgvector
-- from the PRD remain future migrations, not dependencies of the implemented paths.
CREATE TABLE IF NOT EXISTS vi_state (
    id integer PRIMARY KEY CHECK (id = 1),
    data jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

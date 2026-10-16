-- Idempotent schema upgrade; migrations are also applied by the API and worker.
CREATE TABLE IF NOT EXISTS vulnerabilities (
 id text PRIMARY KEY,
 data jsonb NOT NULL,
 priority_score smallint NOT NULL CHECK (priority_score BETWEEN 0 AND 1000),
 cvss double precision NOT NULL DEFAULT 0,
 epss_score double precision NOT NULL DEFAULT 0,
 published text NOT NULL DEFAULT '',
 ssvc_decision text NOT NULL DEFAULT 'Unassessed',
 seen_wild boolean NOT NULL DEFAULT false,
 is_zeroday boolean NOT NULL DEFAULT false,
 ecosystem text NOT NULL DEFAULT '',
 vendor text NOT NULL DEFAULT '',
 search_text tsvector GENERATED ALWAYS AS (to_tsvector('simple', coalesce(data->>'id','') || ' ' || coalesce(data->>'title','') || ' ' || coalesce(data->>'description','') || ' ' || coalesce(data->>'vendor','') || ' ' || coalesce(data->>'product','') || ' ' || coalesce(data->>'purl',''))) STORED,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS vuln_priority_cursor ON vulnerabilities(priority_score DESC,id DESC);
CREATE INDEX IF NOT EXISTS vuln_published_cursor ON vulnerabilities(published DESC,id DESC);
CREATE INDEX IF NOT EXISTS vuln_epss_cursor ON vulnerabilities(epss_score DESC,id DESC);
CREATE INDEX IF NOT EXISTS vuln_cvss_cursor ON vulnerabilities(cvss DESC,id DESC);
CREATE INDEX IF NOT EXISTS vuln_search ON vulnerabilities USING gin(search_text);
CREATE INDEX IF NOT EXISTS vuln_data ON vulnerabilities USING gin(data jsonb_path_ops);
CREATE TABLE IF NOT EXISTS intelligence_entities (
 kind text NOT NULL CHECK(kind IN ('actors','ransomware','patches','rules','relationships','products')),
 id text NOT NULL,
 source text NOT NULL,
 data jsonb NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(kind,id,source)
);
CREATE INDEX IF NOT EXISTS entities_kind ON intelligence_entities(kind);
CREATE INDEX IF NOT EXISTS entities_data ON intelligence_entities USING gin(data jsonb_path_ops);
CREATE TABLE IF NOT EXISTS ingestion_checkpoints (
 source_name text PRIMARY KEY,
 data jsonb NOT NULL,
 lease_until timestamptz,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ingestion_jobs (
 id bigserial PRIMARY KEY,
 source_name text NOT NULL,
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','failed')),
 created_at timestamptz NOT NULL DEFAULT now(),
 finished_at timestamptz,
 detail text
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_source_job ON ingestion_jobs(source_name) WHERE status IN ('queued','running');
CREATE TABLE IF NOT EXISTS vex_documents (
 id text PRIMARY KEY,
 data jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS audit_events (
 id bigserial PRIMARY KEY,
 action text NOT NULL,
 subject text NOT NULL,
 detail jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS system_state (id integer PRIMARY KEY, revision bigint NOT NULL DEFAULT 0);
INSERT INTO system_state(id,revision) VALUES(1,0) ON CONFLICT DO NOTHING;
-- No legacy vi_state data is imported: it contains fabricated demo intelligence.
DO $$
BEGIN
 IF to_regclass('public.vi_state') IS NOT NULL THEN
   INSERT INTO vex_documents(id,data)
   SELECT doc->>'@id',doc FROM public.vi_state,
   LATERAL jsonb_array_elements(COALESCE(data->'vex','[]'::jsonb)) doc
   WHERE doc->>'@id' IS NOT NULL ON CONFLICT DO NOTHING;
   DROP TABLE public.vi_state;
 END IF;
END $$;

ALTER TABLE ingestion_checkpoints ADD COLUMN IF NOT EXISTS lease_owner text;
UPDATE ingestion_checkpoints SET lease_until=NULL,data=data||jsonb_build_object('status','Pending') WHERE lease_owner IS NULL AND data->>'status'='Running';

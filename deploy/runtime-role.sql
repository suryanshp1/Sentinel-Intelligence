-- Applied by scripts/setup.mjs through the administrator connection.
-- The API/worker role owns its schema objects, but has no cluster-administrator powers.
GRANT CONNECT ON DATABASE sentinel TO sentinel_app;
GRANT USAGE, CREATE ON SCHEMA public TO sentinel_app;
DO $$ DECLARE item record; BEGIN
 FOR item IN SELECT tablename FROM pg_tables WHERE schemaname='public' LOOP
  EXECUTE format('ALTER TABLE public.%I OWNER TO sentinel_app',item.tablename);
 END LOOP;
 FOR item IN SELECT sequencename FROM pg_sequences WHERE schemaname='public' LOOP
  EXECUTE format('ALTER SEQUENCE public.%I OWNER TO sentinel_app',item.sequencename);
 END LOOP;
END $$;
ALTER ROLE sentinel_app SET statement_timeout = '30s';
ALTER ROLE sentinel_app SET lock_timeout = '5s';

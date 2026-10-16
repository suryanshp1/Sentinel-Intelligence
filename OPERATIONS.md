# Operations

## Storage and upgrades

PostgreSQL is the source of truth. API/worker startup applies idempotent migrations under a database advisory lock. Import pages and checkpoints commit together. Before an upgrade, back up the database and retain the previous image. Test upgrades against a restored copy first; schema changes are not automatically reversible. The old demonstration snapshot is deliberately not imported into the intelligence tables. Existing local VEX documents are preserved.

```sh
node scripts/backup.mjs
```

Backups are custom-format PostgreSQL dumps written under ignored `backups/` with restrictive permissions. Copy them to your encrypted backup storage with a retention policy. They include local VEX and audit data; feed caches are disposable. Back up `.env` separately in a secrets manager.

Restore to a **new empty database** first, using the correct admin role for your deployment:

```sh
docker compose exec -T postgres createdb -U sentinel -O sentinel_app sentinel_restore
docker compose exec -T postgres pg_restore -U sentinel -d sentinel_restore --no-owner --role=sentinel_app < backups/YOUR_BACKUP.dump
```

Inspect the restored database and verify record counts before changing a deployment's DATABASE_URL. Never restore over an active database. `docker compose down` retains named volumes; `down --volumes` destroys them and is only appropriate for disposable test stacks.

## Credentials and access

`VI_API_TOKEN` is a single operator secret (minimum 32 characters in production). Rotation requires replacing it in the secret environment and restarting the API; sessions are namespaced by its hash and old sessions cease to authenticate. Valkey stores session handles, not the raw operator token. Sessions expire after eight hours. Logout revokes the current session. Production requires HTTPS for Secure cookies.

`POSTGRES_PASSWORD` is the database admin credential; `VI_DB_PASSWORD` belongs to `sentinel_app`, which owns application schema objects but has no superuser/create-database/create-role privileges. Changing an environment variable alone does not rotate an existing PostgreSQL role password; rotate the role inside PostgreSQL in a controlled session and update app secrets together. Do not expose PostgreSQL or Valkey to public networks. The included connection uses plaintext database transport on the private Docker network; remote databases require a TLS-capable connection implementation before deployment outside that trust boundary.

`VI_PUBLIC_ORIGIN` must match the browser's origin exactly. Public HTTPS overlay derives it from `VI_PUBLIC_HOST`. Cross-origin mutations are rejected. REST and GraphQL require authentication; distributed Valkey quotas fail closed when unavailable. Login attempts have a deployment-wide rate limit. There are no tenant boundaries or individual user roles in this release.

## Source operations

Data sources shows the last success, last-run count, status, and upstream error. Sync now creates a durable job; duplicate queued/running jobs for the same source are deduplicated. It does not bypass an upstream backoff. The worker polls every ten seconds and caps concurrent source runs at four.

HTTP 429/503 and provider outages are normal observable failures: wait for the persisted retry time, configure an optional free provider key, or investigate the upstream service. Do not replace missing results with fixtures. NVD backfill is gradual; EPSS and detection mappings cover the ingested subset, not every published CVE. MSRC begins with recent update documents, not a complete KB history. Ransomware names do not imply verified CVE attribution.

Graceful SIGTERM aborts active worker tasks and releases that worker's leases. After a hard kill, source leases expire after 15 minutes and abandoned queued jobs are recovered after their timeout. Checkpoints preserve already committed pages. Feed HTTP response bodies and expanded rule archives are bounded; rules are stored as references and never executed.

Vendor CSAF/OpenVEX imports require files under `VI_VEX_IMPORT_DIR`. Supply that directory from a publisher verification process. The current importer does not establish signatures or publisher identity. Leave `VI_TRUST_LOCAL_VEX=false` unless your operator process explicitly accepts locally authored statements. Do not present this option as signature validation.

## Monitoring

- `/health`: API process liveness.
- `/readyz`: PostgreSQL and Valkey readiness; use it for load balancer readiness checks.
- `/api/metrics`: authenticated Prometheus text metrics.
- `node scripts/status.mjs`: local catalog counts and source error summary.
- Container stdout/stderr: structured source completion events and API logs.

The Compose stack restarts failed services but does not include a hosted alerting service. Add your open-source monitoring system, backup schedule, disk/volume alerts, and source freshness alerts for an operational deployment. Set a retention policy for audit events, ingestion jobs, and feed caches based on your capacity. Capacity, failover, and penetration tests have not been certified by this implementation.

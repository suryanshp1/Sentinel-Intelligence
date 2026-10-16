# Roadmap

This roadmap describes opportunities, not delivery commitments. Discuss substantial work in an issue before starting. See [IMPLEMENTATION.md](IMPLEMENTATION.md) for the detailed scope matrix and [MCP.md](MCP.md) for the MCP design.

## Available today

- Continuous public-source ingestion with provenance, checkpoints, retries, and visible failures.
- PostgreSQL catalog search, typed filters, facets, and keyset pagination.
- CVE investigation, actor and ransomware profiles, affected package and KB lookup.
- Versioned-PURL SBOM analysis with live OSV matching and persisted OpenVEX statements.
- REST, GraphQL, OpenAPI, exports, and nine read-only MCP tools over HTTP or the stdio bridge.
- A responsive React workspace, local preferences, Docker Compose, and an HTTPS deployment overlay.

## Reliability and evidence quality

- Expand deterministic adapter fixtures and failure/recovery coverage.
- Improve historical backfill visibility and source coverage reporting.
- Optimize entity queries and benchmark a larger catalog.
- Exercise backup/restore, upgrades, and failure recovery on a repeatable schedule.
- Expand accessibility and browser regression coverage.

## Integrations and AI clients

- Scoped, revocable MCP credentials and per-client audit identity.
- OAuth discovery and authorization for hosted AI connectors.
- Newer MCP protocol revisions and a tested client compatibility matrix.
- Bounded SBOM tools with explicit outbound network controls.
- Generated API clients and fuller TAXII interoperability.

## Broader intelligence and trust

- Publisher identity and signature verification for vendor VEX/CSAF.
- More complete SSVC decision support and CVSS v4 computation.
- Broader historical KB/advisory coverage and verified actor attribution.
- Additional connectors where upstream access and licensing support them.

## Deployment evolution

- SSO, RBAC, multiple users, and tenant isolation.
- High availability, monitoring integrations, and capacity testing.
- Release artifacts, supply-chain review, and a versioned support policy.

These items are not implemented unless explicitly marked as available. Proposals should preserve provenance, unknown-value semantics, bounded resource use, and the existing conservative VEX policy.

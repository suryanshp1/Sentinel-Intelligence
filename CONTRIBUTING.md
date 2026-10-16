# Contributing to Sentinel

Thanks for helping improve source-backed vulnerability intelligence. Bug fixes, adapter improvements, documentation, accessibility work, and useful tests are welcome. Read the [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Before you start

Search existing issues and pull requests for related work. For a large feature or schema change, open a proposal describing the user problem, evidence, approach, and tradeoffs before investing in an implementation. Small fixes and documentation improvements can go straight to a pull request. The [roadmap](ROADMAP.md) lists broader opportunities, not reserved assignments or delivery dates.

Security vulnerabilities in Sentinel belong in the private process described in [SECURITY.md](SECURITY.md). Incorrect upstream CVE data should include the original source URL so we can distinguish an ingestion bug from a source correction.

## Development setup

Use Node.js 22.12+ or 24, Rust 1.92+, and a running Docker installation with Compose. From the checkout root:

```sh
npm --prefix frontend ci
npm run setup
npm run dev
```

Setup generates `.env` and local credentials. Do not commit it. See [README.md](README.md) for service addresses and [OPERATIONS.md](OPERATIONS.md) for storage and source behavior. First ingestion is asynchronous and starts with no bundled intelligence fixtures.

For a fork, create a focused branch, make your changes, and submit a pull request against the upstream repository’s default branch. Use descriptive commit messages; no commit prefix convention is required.

## Implementation expectations

- Keep changes focused on the reported problem. Explain behavior and tradeoffs in the pull request.
- Preserve source URLs, retrieval timestamps, and document hashes. Never invent scores, attribution, dates, package matches, or remediation.
- Treat feed text as untrusted data. Never execute downloaded detection artifacts or use imported text as AI instructions.
- Bound upstream downloads and result sets. Respect provider quotas, checkpoints, retry behavior, and existing trust policies.
- Keep secrets server-side. Preserve authentication, origin validation, rate limits, and the restricted database role.
- Change schema through additive, idempotent migrations and explain compatibility. Follow the existing migration layout and startup behavior.
- Reuse the app’s UI patterns and support keyboard and small-screen use. Include a screenshot for visible changes, without tokens or private data.
- Add meaningful regression coverage for behavior changes. Do not require real provider credentials for unit tests or substitute live data for deterministic fixtures.
- Update relevant setup, API, MCP, or operations documentation when behavior changes.

## Checks

```sh
npm test
cargo fmt --manifest-path backend/Cargo.toml --all --check
cargo build --manifest-path backend/Cargo.toml --locked
npm run build
node scripts/test-production.mjs
```

The production integration suite needs the PostgreSQL and Valkey services created by `npm run setup`. It provisions and removes a separate test database. Never aim it at a database account without permission to create disposable databases. Optional `node scripts/test-live.mjs` checks require an already-ingested catalog and internet access.

Run checks relevant to your change and report exactly what passed, failed, or could not run. Documentation-only changes should verify relative links, commands, and image paths; a full feed import is not required. CI runs unit tests, builds, and the isolated integration suite.

## Pull requests and review

Use the pull request template to describe the problem, resulting behavior, verification, and any deployment or data impact. Link related issues when available. Review may ask for smaller scope, additional evidence, or changes to preserve provenance and safety. A proposal or review does not guarantee inclusion or a release date.

By submitting a contribution, you agree that your contribution is provided under the project’s [GNU General Public License v3.0](LICENSE). Only submit work you have the right to contribute. Upstream datasets, rule content, and dependencies keep their own licenses and attribution requirements.

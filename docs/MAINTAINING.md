# Maintainer publication checklist

The source tree includes contribution guidance, a code of conduct, a security policy, issue and PR templates, dependency update configuration, and CI. GitHub repository settings and ownership must be configured separately; files alone do not enable those settings.

Before making a public repository available:

- Confirm the project license and the rights to contributed code and screenshots. Preserve third-party attribution in SOURCES.md.
- Review the complete Git history for secrets and private artifacts. Ignoring a file does not remove a previously committed copy. Rotate any credential that has been exposed.
- Set the repository description, topics, and default branch. Suggested description: “Self-hosted vulnerability intelligence with source-backed CVE research, SBOM analysis, and MCP tools. Rust, React, PostgreSQL.” Suggested topics: vulnerability-management, threat-intelligence, cve, sbom, openvex, mcp, rust, react, self-hosted.
- Enable issues and private vulnerability reporting. Publish a real private contact channel for security and conduct reports, and update SECURITY.md and CODE_OF_CONDUCT.md.
- Enable dependency alerts and review the configured Dependabot updates.
- Configure branch protection or repository rulesets requiring pull request review and the Verify workflow’s test check. Verify the check name after its first run.
- Run CI on a clean checkout. Never provide production credentials to pull request workflows.
- Add actual maintainers or CODEOWNERS only when the people or teams and their responsibilities are confirmed. Do not invent owners.

For a release:

1. Review the roadmap and document delivered behavior, breaking changes, and known limitations in release notes.
2. Run unit tests, formatting, builds, isolated integration tests, and applicable deployment checks.
3. Review dependency and source-data attribution; do not bundle feed caches, third-party rule archives, secrets, or private data without the necessary rights.
4. Document upgrade and migration effects and test against a restored database copy.
5. Choose and tag the release version consistently across application manifests. Do not infer stable support from a successful development build.

No repository URL, owner identity, support mailbox, hosted demo, package registry, or release channel is assumed by these files. Add verified links and release badges after those destinations exist.

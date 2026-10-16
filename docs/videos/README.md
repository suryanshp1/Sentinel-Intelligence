# Application walkthrough

[`sentinel-walkthrough.mp4`](sentinel-walkthrough.mp4) is a silent recording of the real Sentinel app, captured on 16 October 2026 at 1440 × 960. It uses the existing local catalog of public-source intelligence and the workbench's built-in CycloneDX manifest template. No operator token, credentials, or private software inventory is shown.

The walkthrough covers:

1. The intelligence overview and source-reported metrics.
2. Searching for CVE-2021-44228 and opening its evidence sources, retrieval timestamps, and scoring explanation.
3. Searching for APT28 and viewing its MITRE ATT&CK profile.
4. Loading the sample SBOM and submitting it for analysis. The recording leaves the workbench while the live OSV request is pending; it does not show analysis results.
5. Data-source freshness and last-run status.

Counts and source status describe the captured installation, not a bundled demo dataset or a coverage guarantee. Upstream intelligence retains its attribution and terms; see [SOURCES.md](../../SOURCES.md).

The MP4 uses H.264 with a `yuv420p` pixel format and fast-start metadata for browser playback. The README links its preview image and a text fallback to the tracked video so the asset remains available without an external video host.

To refresh it, record an authenticated local session after signing in, use only public or non-sensitive inputs, and review the full recording for credentials or private data. Keep raw recordings and authentication state under ignored `output/playwright/`; copy only the reviewed MP4 into this directory. Update the README duration and workflow description when the recording changes.

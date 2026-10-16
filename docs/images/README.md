# Application screenshots

These PNG files are actual Sentinel application captures, copied from the local verification output into a tracked documentation directory. They are not generated product mockups. Runtime artifacts under `output/` remain ignored.

| File | View | Original capture |
|---|---|---|
| `overview.png` | Intelligence overview | `output/playwright/live-overview-desktop.png` |
| `threat-actors.png` | MITRE ATT&CK APT28 investigation | `output/playwright/live-actor-desktop.png` |
| `sbom-workbench.png` | SBOM analysis and advisory findings | `output/playwright/live-sbom-desktop.png` |

Captures were taken on 16 October 2026 from a populated local installation. Counts differ between captures as ingestion progresses. A fresh installation starts with no intelligence fixtures. The visible intelligence retains its upstream attribution and terms; see [SOURCES.md](../../SOURCES.md). No operator token, database credentials, or private inventory is included in these images.

When refreshing a screenshot, capture the real application with public or non-sensitive test input, review the image for secrets, retain a descriptive filename and alt text, and update this record. Screenshots should not imply live corpus totals or capabilities that the application does not provide.

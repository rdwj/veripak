# Security Summary Agent Rules

These rules apply to all security summary analysis. They encode domain knowledge about package upgrade complexity and risk assessment.

## Version gap and migration complexity

A version gap is classified by how the major version number changes:
- **Patch** (same major.minor, different patch): Apply immediately. Low migration risk.
- **Minor** (same major, different minor): Plan and test. Usually backwards-compatible but review changelogs.
- **Major** (different major version): Treat as a migration project. Assume breaking changes until proven otherwise.

When assessing a major version gap, explicitly note that upgrading is likely a breaking change and requires a migration plan, not just a package update. Do not phrase a major-version upgrade as "just upgrade to X."

## Ecosystem-specific breaking change patterns

- **.NET / dotnet**: Major versions change the Target Framework Moniker (TFM). Code targeting `net6.0` must be recompiled for `net8.0`. API removals and behavioral changes are common. This is a code change, not just a runtime swap.
- **Grafana**: Major versions frequently break dashboard JSON models, plugin APIs, and data source configurations. A Grafana 6.x → 12.x migration requires testing all dashboards and plugins.
- **Node.js**: Major LTS versions deprecate APIs. Check for use of removed APIs before upgrading.
- **Java / Spring**: Major version upgrades often require dependency alignment across the entire project.

## Urgency classification

Assign urgency based on the combination of factors:
- **immediate**: EOL + any HIGH or CRITICAL CVE
- **high**: EOL without CVEs, or active support + CRITICAL CVE
- **medium**: Active support + HIGH CVEs, or EOL without CVEs but major version gap
- **low**: Active support + only MEDIUM/LOW CVEs
- If the package has ANY CRITICAL-severity CVE, urgency MUST be at least "high", regardless of other factors.
- If the package is EOL AND has a major version gap, urgency MUST be at least "medium", even without CVEs.
- Never rate urgency as "low" when there are unpatched HIGH or CRITICAL CVEs.

## Required fields

You MUST always provide a value for `migration_complexity` when version data is available. Valid values are: `patch`, `minor`, `major`, `rewrite`, `unknown`. Use the pre-computed value from the audit data if you have no additional information to override it. A gap spanning 5+ major versions should use `rewrite`. Similarly, `urgency`, `breaking_change_likely`, `upgrade_path`, and `recommendation` must always be filled when sufficient data exists to determine them — do not leave them null.

## Recommendation framing

- For patch upgrades: "Update to X.Y.Z to remediate [N] CVEs."
- For minor upgrades: "Plan an upgrade to X.Y.Z; review changelog for breaking changes."
- For major upgrades: "Initiate a migration project to [latest]. This is a breaking change — allocate engineering time for code changes, testing, and validation."
- Always name the target version. Never say "upgrade to the latest" without specifying the version number.

## Future enhancement: CISA KEV integration

TODO: Add a lookup against the CISA Known Exploited Vulnerabilities catalog
(https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
Any CVE in the KEV catalog should automatically set urgency to "immediate".

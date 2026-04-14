# Changelog

All notable changes to the CS&T Instance Hardening Checks project are documented here. Versions correspond to the Update Set XML releases in [`dist/`](dist/).

---

## v1.6a - 2026-04-14

### Added
- **cstaces-12** (local-account-login) — Detects active users logging in via local DB authentication instead of SSO; queries `sys_user_login_history` for DB auth events in the last 30 days (Level 2)
- **cstaces-13** (role-mgt-v2) — Checks whether the Role Management v2 plugin (`com.glide.role_management.inh_count`) is installed (Level 2)
- Added `short_description`, `description`, `resolution_details`, and `documentation_url` for both new checks

### Changed
- Updated scripts for cstaces-4a (secadmin) and cstaces-5b (active OAuth) with latest instance versions
- Updated scripts for cstaces-1a (admin users) with last-login-days-ago in finding details
- Total checks: 44 (up from 42), total m2m records: 44
- Regenerated README with all 47 check entries across 5 suites (including multi-suite mappings)

### Removed
- Orphaned `cstaces-12-local-db-logins` source files (superseded by `cstaces-12-local-account-login` after instance import)

## v1.6 - 2026-04-14

### Added
- cstaces-12 and cstaces-13 check records imported to instance and added to update set
- Updated check scripts from instance development

### Changed
- Total records: 94 (6 suites, 44 m2m, 44 checks)

## v1.5a - 2026-03-26

### Changed
- Replaced incorrect KB0856250 documentation links across all Level 1 and Level 2 checks with topic-specific references:
  - Admin/elevated privilege checks (1a, 1b) → ServiceNow Elevated Privilege Roles docs
  - Inactive user checks (1c, 1c2) → KB0999382 (inactive users should not retain roles/licenses)
  - Impersonation checks (3b, 3b2) → ServiceNow Impersonate a User docs
  - Security admin check (4a) → KB0688286 (Security Admin role / High Security plugin)
  - Integration admin check (5a) → ServiceNow Internal Integration Users docs
  - ACL modification check (4b) → ServiceNow Access Control Rules docs
  - Self role grant check (4c) → ServiceNow Elevated Privilege Roles docs
- Regenerated README scripted checks sections from source files
- Regenerated review spreadsheet with corrected URLs

## v1.5 - 2026-03-26

### Changed
- Restructured suite-to-check mappings (42 m2m records, down from 44)
- Refreshed all check scripts and metadata from source files
- Incremented sys_mod_count and updated timestamps for all records

## v1.4 - 2026-03-20

### Added
- 22 Level Knowledge checks (cstaces-11a through 11v) covering Knowledge Base security: user criteria enforcement, public access controls, guest denial, ACL auditing, commenting restrictions, and more
- `resolution_details` for all Level 1, 2, 3, and Next checks (previously empty)
- `documentation_url` for all Level 1, 2, 3, and Next checks (previously empty)
- README now includes full scripted checks sections with embedded JavaScript for all 5 suites
- `parse_update_set.py` — extracts checks from Update Set XML into suite-based source files
- `update_metadata.py` — bulk-updates check metadata (resolution details, documentation URLs, short descriptions)
- `generate_update_set.py` — generates new Update Set XML from source files

### Changed
- Fixed truncated `short_description` fields on all 22 Level Knowledge checks (ServiceNow's ~80-char field limit)
- README restructured with collapsible script blocks per check

## v1.3 - 2026-03-20

### Added
- Level Knowledge suite with 22 knowledge base security checks
- 2 additional m2m mappings (cstaces-4a in Level 1 + Level 2, cstaces-5b in Level 2 + Level Next)

### Changed
- Total checks: 42 (up from 20 in v1.2b)
- Total m2m records: 44

## v1.2b - 2026-03-11

### Fixed
- Fixed missing `scan_check_suite_check` m2m records that prevented checks from appearing in their suites

## v1.2a - 2026-03-05

### Changed
- README refactored with scan levels (Level 1, 2, 3, Next) organizational structure
- Check descriptions and metadata improvements

## v1.1 - 2026-03-02

### Changed
- README cleanup and formatting improvements
- Scan check refinements

## v1 - 2026-02-28

### Added
- Initial Update Set with 20 scan checks across 5 suites:
  - **Level 1** — Admin users, high-privilege roles, inactive users, impersonation, security_admin, integration admins
  - **Level 2** — Security admin population, ACL modifications, self role grants, encryption configs
  - **Level 3** — Overly permissive ACLs, dangerous ACL scripts, domain separation
  - **Level Next** — OAuth apps, UI policy bypass, business rule privilege escalation, session hardening, MFA, scheduled jobs
- 6 scan check suites (including empty "CS&T ACES Additional Instance Hardening" placeholder)
- Initial README with installation and usage instructions

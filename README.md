# SN Account Instance Hardening

An Instance Scan suite and checks for auditing ServiceNow instances for security misconfigurations and least privilege violations.

## Overview

This repository contains a ServiceNow Update Set with an Instance Scan suite and individual scan checks that assess common security configuration gaps across identity, access control, privileged activity, and platform hygiene.

## Getting Started

### Download the Update Set

1. Download the update set XML from the [`dist/`](dist/) directory: **[scans v1.xml](dist/scans%20v1.xml)**
2. You can click **Code > Download ZIP** on this repo, or download the raw file directly.

### Import and Commit the Update Set

1. Navigate to **System Update Sets > Retrieved Update Sets**
2. Click **Import Update Set from XML**
3. Select the downloaded `scans v1.xml` file and upload it
4. Open the retrieved update set named **scans v1**
5. Click **Preview Update Set** and review any conflicts
6. Click **Commit Update Set** to apply the scan suite and checks to your instance

> For more information, see the official ServiceNow documentation:
> - [Import an update set](https://docs.servicenow.com/bundle/latest/page/build/system-update-sets/task/t_SaveAnUpdateSetAsALocalFile.html)
> - [Commit a remote update set](https://docs.servicenow.com/bundle/latest/page/build/system-update-sets/task/t_CommitARemoteUpdateSet.html)

---

<details>
<summary><h2>Instance Scan</h2></summary>

Instance Scan is a diagnostic framework built into the ServiceNow platform that runs checks against your instance configuration and identifies issues. The update set in this repository installs a scan suite and checks that target common security hardening gaps.

> **Official documentation:** [Instance Scan](https://docs.servicenow.com/bundle/latest/page/administer/health-scan/concept/hs-landing-page.html)

### Running Checks Manually

1. Navigate to **Instance Scan > Suites**
2. Open the suite installed by this update set (e.g. **CST Additional checks global**)
3. Click **Scan Now** to execute all checks in the suite
4. Alternatively, run individual checks from **Instance Scan > Checks** by opening a check and clicking **Scan Now**

### Scheduling Regular Execution

1. Navigate to **Instance Scan > Suite Schedules**
2. Click **New** to create a new schedule
3. Select the scan suite installed by this update set
4. Set the **Run** frequency (e.g. Weekly, Daily) and configure the schedule as needed
5. Save the schedule record

Scheduled scans run automatically and generate new results each execution. Consider running scans at least weekly to catch configuration drift.

### Reviewing and Muting Findings

1. Navigate to **Instance Scan > Findings** to see all findings across scan runs
2. Review each finding to determine if it represents a genuine issue or an accepted configuration
3. To mute a known-good or acceptable finding:
   - Open the finding record
   - Click **Mute Finding**
   - Provide a justification in the mute reason field
4. Muted findings are excluded from future scan result summaries but remain visible for audit purposes

> **Tip:** Periodically review muted findings to ensure the justifications are still valid.

### Creating Tasks for Remediation

1. From an open finding record, click **Create Task** (or **Create Security Task** if available)
2. Assign the task to the appropriate team or individual
3. Set a priority and due date based on the finding severity
4. Track remediation progress through the task record
5. Once remediated, re-run the scan to verify the finding is resolved

</details>

---

<details>
<summary><h2>Security Center</h2></summary>

Security Center provides a centralized dashboard for monitoring the security posture of your ServiceNow instance. Instance Scan results feed into Security Center, giving you a consolidated view of findings, scores, and trends over time.

> **Official documentation:** [Security Center](https://docs.servicenow.com/bundle/latest/page/administer/security-center/concept/security-center-landing-page.html)

### Running Checks Manually

1. Navigate to **Security Center > Security Center** (or use the Security Center dashboard)
2. View the overall security score and category breakdowns
3. Click into a specific category or check to see individual results
4. To trigger a manual refresh of scan data, run the associated Instance Scan suite (see the Instance Scan section above) — results automatically flow into Security Center

### Scheduling Regular Execution

Security Center scores update automatically when Instance Scan runs execute. To ensure regular updates:

1. Set up a scheduled Instance Scan suite execution (see the Instance Scan scheduling section above)
2. Security Center dashboards and scores will reflect the latest scan results after each run
3. Navigate to **Security Center > Settings** to configure score thresholds and notification preferences

### Reviewing and Muting Findings

1. Navigate to **Security Center > Security Center** and click into a category score
2. Review the listed findings contributing to the score
3. To mute a finding that is known-good or an accepted risk:
   - Open the finding
   - Click **Mute** or **Accept Risk**
   - Provide a business justification
4. Muted findings are factored out of the security score but remain auditable
5. Use the **Muted Findings** view to review all currently suppressed items

### Creating Security Tasks for Remediation

1. From the Security Center dashboard, click into a finding that requires action
2. Click **Create Security Task**
3. Fill in the task details:
   - **Assigned to**: the person or team responsible for remediation
   - **Priority**: align with finding severity
   - **Due date**: set an appropriate remediation window
4. Security tasks appear under **Security Center > Security Tasks**
5. Track progress and update the task as work is completed
6. Once remediated, re-run the scan to confirm the finding is cleared and the security score improves

</details>

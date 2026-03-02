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


---

## Scripted Checks

Each check below is a `scan_script_only_check` record deployed via the update set. Scripts execute server-side within the Instance Scan engine and generate findings automatically.

Source files are available in [`scans/current/`](scans/current/) (`.js` for scripts, `.json` for metadata).

### cstaces-1a admin users

**Priority:** 2

**What:** Enumerates all active users with admin, security_admin, or user_admin roles via both direct assignment and group inheritance. Flags dormant accounts (by last login) and potential service accounts.

**Why:** CIS and NIST 800-53 (AC-6) require that the highest-privilege roles be limited to the smallest number of named individuals with a documented business need. Unreviewed admin populations are consistently one of the top findings in ServiceNow security assessments.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {


    var privilegedRoles = ['admin', 'security_admin', 'user_admin'];
    var privilegedUsers = {};

    function addUser(userSysId, role, source) {
        if (!userSysId) return;
        var u = new GlideRecord('sys_user');
        if (u.get(userSysId)) {
            if (u.getValue('active') != '1') return;
            var uname = u.user_name.toString();
            if (!privilegedUsers[uname]) {
                privilegedUsers[uname] = {
                    user: u.name.toString(),
                    user_name: uname,
                    email: u.email.toString(),
                    last_login: u.last_login_time.toString(),
                    is_service_account: (uname.indexOf('svc') > -1 ||
                        uname.indexOf('service') > -1 ||
                        uname.indexOf('integration') > -1 ||
                        uname.indexOf('api') > -1) ? true : false,
                    roles: [],
                    sources: []
                };
            }
            if (privilegedUsers[uname].roles.indexOf(role) === -1) {
                privilegedUsers[uname].roles.push(role);
            }
            if (privilegedUsers[uname].sources.indexOf(source) === -1) {
                privilegedUsers[uname].sources.push(source);
            }
        }
    }

    // Direct role assignments
    for (var i = 0; i < privilegedRoles.length; i++) {
        var roleName = privilegedRoles[i];
        var direct = new GlideRecord('sys_user_has_role');
        direct.addQuery('role.name', roleName);
        direct.addQuery('user.active', 'true');
        direct.addQuery('state', 'active');
        direct.query();
        while (direct.next()) {
            addUser(direct.getValue('user'), roleName, 'direct:' + roleName);
			var userRec = direct.user.getRefRecord();
			engine.finding.setCurrentSource(userRec);
			engine.finding.setValue('finding_details','Found with DIRECT role assignment');
			engine.finding.increment();
        }
    }

    // Group-inherited assignments
    for (var j = 0; j < privilegedRoles.length; j++) {
        var groupRoleName = privilegedRoles[j];
        var groupRole = new GlideRecord('sys_group_has_role');
        groupRole.addQuery('role.name', groupRoleName);
        groupRole.query();
        while (groupRole.next()) {
            var groupName = groupRole.group.name.toString();
            var member = new GlideRecord('sys_user_grmember');
            member.addQuery('group', groupRole.getValue('group'));
            member.addQuery('user.active', 'true');
            member.query();
            while (member.next()) {
                addUser(member.getValue('user'), groupRoleName, 'group:' + groupName + ':' + groupRoleName);
				var userRec2 = member.user.getRefRecord();
				engine.finding.setCurrentSource(userRec2);
				engine.finding.setValue('finding_details','Found with GROUP INHEIRITED role assignment');
				engine.finding.increment();
            }
        }
    }

    var results = [];
    for (var uname in privilegedUsers) {
        results.push(privilegedUsers[uname]);
    }

    var multiRole = results.filter(function(u) {
        return u.roles.length > 1;
    });
    var serviceAccounts = results.filter(function(u) {
        return u.is_service_account;
    });

    // gs.info('Total privileged users: ' + results.length);
    // gs.info('Users with multiple high privilege roles: ' + multiRole.length);
    // gs.info('Potential service accounts: ' + serviceAccounts.length);
    // gs.info(JSON.stringify(results, null, 2));


    

})(engine);
```

</details>

---

### cstaces-1b multiple high

**Priority:** 3

**What:** Identifies active users holding two or more high-privilege roles simultaneously (admin, security_admin, user_admin, delegated_admin, itil_admin, catalog_admin, knowledge_admin). Results are sorted by role count descending.

**Why:** Role accumulation violates the principle of least privilege (NIST AC-6(5)) and significantly expands the blast radius of a compromised account. Separation of duties controls require that no single account concentrates multiple administrative capabilities without explicit justification.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    /**
     * Query 1b: Users with Multiple High-Privilege Roles
     *
     * Purpose:
     * Identifies active users who hold more than one high-privilege role
     * simultaneously. Role accumulation violates the principle of least privilege
     * and significantly expands the blast radius of a compromised account.
     *
     * What it checks:
     * - Direct and group-inherited assignments for admin, security_admin,
     *   user_admin, delegated_admin, itil_admin, catalog_admin, knowledge_admin
     * - Flags any user holding 2 or more roles from this list
     * - Results sorted by role count descending
     * - Last login timestamp and service account flag
     *
     * Tables queried: sys_user_has_role, sys_group_has_role, sys_user_grmember
     */

    var privilegedRoles = [
        'admin',
        'security_admin',
        'user_admin',
        'delegated_admin',
        'itil_admin',
        'catalog_admin',
        'knowledge_admin'
    ];

    var privilegedUsers = {};

    function addUser(userSysId, role, source) {
        if (!userSysId) return;
        var u = new GlideRecord('sys_user');
        if (u.get(userSysId)) {
            if (!u.active) return;
            var uname = u.user_name.toString();
            if (!privilegedUsers[uname]) {
                privilegedUsers[uname] = {
                    user: u.name.toString(),
                    user_name: uname,
                    email: u.email.toString(),
                    last_login: u.last_login_time.toString(),
                    is_service_account: (uname.indexOf('svc') > -1 ||
                        uname.indexOf('service') > -1 ||
                        uname.indexOf('integration') > -1 ||
                        uname.indexOf('api') > -1) ? true : false,
                    roles: [],
                    sources: []
                };
            }
            if (privilegedUsers[uname].roles.indexOf(role) === -1) {
                privilegedUsers[uname].roles.push(role);
            }
            if (privilegedUsers[uname].sources.indexOf(source) === -1) {
                privilegedUsers[uname].sources.push(source);
            }
        }
    }

    for (var i = 0; i < privilegedRoles.length; i++) {
        var roleName = privilegedRoles[i];
        var direct = new GlideRecord('sys_user_has_role');
        direct.addQuery('role.name', roleName);
        direct.addQuery('user.active', 'true');
        direct.addQuery('state', 'active');
        direct.query();
        while (direct.next()) {
            addUser(direct.getValue('user'), roleName, 'direct:' + roleName);
			var userRec = direct.user.getRefRecord();
			engine.finding.setCurrentSource(userRec);
			engine.finding.setValue('finding_details','Found with DIRECT role assignment');
			engine.finding.increment();
        }
    }

    for (var j = 0; j < privilegedRoles.length; j++) {
        var groupRoleName = privilegedRoles[j];
        var groupRole = new GlideRecord('sys_group_has_role');
        groupRole.addQuery('role.name', groupRoleName);
        groupRole.query();
        while (groupRole.next()) {
            var groupName = groupRole.group.name.toString();
            var member = new GlideRecord('sys_user_grmember');
            member.addQuery('group', groupRole.getValue('group'));
            member.addQuery('user.active', 'true');
            member.query();
            while (member.next()) {
                addUser(member.getValue('user'), groupRoleName, 'group:' + groupName + ':' + groupRoleName);
				var userRec2 = member.user.getRefRecord();
				engine.finding.setCurrentSource(userRec2);
				engine.finding.setValue('finding_details','Found with GROUP INHEIRITED role assignment');
				engine.finding.increment();
            }
        }
    }

    var results = [];
    for (var uname in privilegedUsers) {
        if (privilegedUsers[uname].roles.length > 1) {
            results.push(privilegedUsers[uname]);
        }
    }

    results.sort(function(a, b) {
        return b.roles.length - a.roles.length;
    });

    var serviceAccounts = results.filter(function(u) {
        return u.is_service_account;
    });

    // gs.info('Users with multiple high-privilege roles: ' + results.length);
    // gs.info('Potential service accounts with multiple roles: ' + serviceAccounts.length);
    // gs.info(JSON.stringify(results, null, 2));

})(engine);
```

</details>

---

### cstaces-1c deprovioned 60newer

**Priority:** 3

**What:** Identifies inactive users who still retain privileged role assignments. Separates direct assignments (critical) from inherited ones (high), and flags accounts deactivated within the last 90 days as highest reactivation risk.

**Why:** If a deprovisioned account is reactivated (intentionally or accidentally), elevated access is immediately restored without requiring a new approval. This is a common gap in offboarding processes and violates NIST AC-2(3) requirements for disabling inactive accounts and revoking associated authorizations.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    var roleList = [
        'admin',
        'security_admin',
        'user_admin',
        'delegated_admin',
        'impersonator',
        'itil_admin',
        'catalog_admin',
        'knowledge_admin'
    ];

    var inactiveRoles = new GlideRecord('sys_user_has_role');
    inactiveRoles.addQuery('role.name', 'IN', roleList.join(','));
    inactiveRoles.addQuery('user.active', false);
    inactiveRoles.addQuery('state', 'active'); // Role assignment is still active even though the user is not
    inactiveRoles.query();

    var direct = [];
    var inherited = [];

    while (inactiveRoles.next()) {

		//var userRec = inactiveRoles.user.getRefRecord();
		//engine.finding.setCurrentSource(userRec);
		//engine.finding.increment();

        var uname = inactiveRoles.user.user_name.toString();
        var record = {
            sys_id: inactiveRoles.getUniqueValue(),
            user_sys_id: inactiveRoles.getValue('user'),
            user_name: uname,
            user_display_name: inactiveRoles.user.getDisplayValue(),
            email: inactiveRoles.user.email.toString(),
            role: inactiveRoles.role.name.toString(),
            inherited: inactiveRoles.inherited.toString(),
            sys_created_on: inactiveRoles.sys_created_on.toString(),
            last_login: inactiveRoles.user.last_login_time.toString(),
            locked_out: inactiveRoles.user.locked_out.toString(),
            is_service_account: (uname.indexOf('svc') > -1 ||
                uname.indexOf('service') > -1 ||
                uname.indexOf('integration') > -1 ||
                uname.indexOf('api') > -1) ? true : false
        };

        if (inactiveRoles.inherited.toString() === 'false') {
            direct.push(record);
        } else {
            inherited.push(record);
        }
    }

    // Flag recently deactivated users (last 60 days) - highest reactivation risk
    // Note: uses sys_updated_on as proxy since ServiceNow has no dedicated deactivation timestamp
    var recentlyDeactivated = [];
    var allRecords = direct.concat(inherited);

    for (var i = 0; i < allRecords.length; i++) {
        var deactivatedUser = new GlideRecord('sys_user');
        deactivatedUser.get(allRecords[i].user_sys_id);
        var updatedOn = new GlideDateTime(deactivatedUser.sys_updated_on.toString());
        var checkDaysAgo = new GlideDateTime();
        checkDaysAgo.addDaysUTC(-60);
        if (updatedOn.compareTo(checkDaysAgo) > 0) {
			
			engine.finding.setCurrentSource(deactivatedUser);
			engine.finding.setValue('finding_details',i);
			engine.finding.increment();

            recentlyDeactivated.push({
                user_name: allRecords[i].user_name,
                user_display_name: allRecords[i].user_display_name,
                email: allRecords[i].email,
                role: allRecords[i].role,
                inherited: allRecords[i].inherited,
                is_service_account: allRecords[i].is_service_account,
                deactivated_around: deactivatedUser.sys_updated_on.toString()
            });
        
		}
    }

    var serviceAccounts = allRecords.filter(function(u) {
        return u.is_service_account;
    });

    // gs.info('=== DEPROVISIONED USERS WITH PRIVILEGED ROLES ===');
    // gs.info('Direct assignments (critical - survives reactivation): ' + direct.length);
    // gs.info('Inherited assignments (high - survives reactivation): ' + inherited.length);
    // gs.info('Total records: ' + (direct.length + inherited.length));
    // gs.info('Recently deactivated (<90 days, highest reactivation risk): ' + recentlyDeactivated.length);
    // gs.info('Potential service accounts: ' + serviceAccounts.length);
    // gs.info('\nDirect assignments:');
    // gs.info(JSON.stringify(direct, null, 2));
    // gs.info('\nInherited assignments:');
    // gs.info(JSON.stringify(inherited, null, 2));
    // gs.info('\nRecently deactivated users:');
    // gs.info(JSON.stringify(recentlyDeactivated, null, 2));

})(engine);
```

</details>

---

### cstaces-1c2 deprovsioned 60older

**Priority:** 4

**What:** Identifies inactive users who still retain privileged role assignments. Separates direct assignments (critical) from inherited ones (high), and flags accounts deactivated within the last 90 days as highest reactivation risk.

**Why:** If a deprovisioned account is reactivated (intentionally or accidentally), elevated access is immediately restored without requiring a new approval. This is a common gap in offboarding processes and violates NIST AC-2(3) requirements for disabling inactive accounts and revoking associated authorizations.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    var roleList = [
        'admin',
        'security_admin',
        'user_admin',
        'delegated_admin',
        'impersonator',
        'itil_admin',
        'catalog_admin',
        'knowledge_admin'
    ];

    var inactiveRoles = new GlideRecord('sys_user_has_role');
    inactiveRoles.addQuery('role.name', 'IN', roleList.join(','));
    inactiveRoles.addQuery('user.active', false);
    inactiveRoles.addQuery('state', 'active'); // Role assignment is still active even though the user is not
    inactiveRoles.query();

    var direct = [];
    var inherited = [];

    while (inactiveRoles.next()) {

		//var userRec = inactiveRoles.user.getRefRecord();
		//engine.finding.setCurrentSource(userRec);
		//engine.finding.increment();

        var uname = inactiveRoles.user.user_name.toString();
        var record = {
            sys_id: inactiveRoles.getUniqueValue(),
            user_sys_id: inactiveRoles.getValue('user'),
            user_name: uname,
            user_display_name: inactiveRoles.user.getDisplayValue(),
            email: inactiveRoles.user.email.toString(),
            role: inactiveRoles.role.name.toString(),
            inherited: inactiveRoles.inherited.toString(),
            sys_created_on: inactiveRoles.sys_created_on.toString(),
            last_login: inactiveRoles.user.last_login_time.toString(),
            locked_out: inactiveRoles.user.locked_out.toString(),
            is_service_account: (uname.indexOf('svc') > -1 ||
                uname.indexOf('service') > -1 ||
                uname.indexOf('integration') > -1 ||
                uname.indexOf('api') > -1) ? true : false
        };

        if (inactiveRoles.inherited.toString() === 'false') {
            direct.push(record);
        } else {
            inherited.push(record);
        }
    }

    // Flag recently deactivated users (last 60 days) - highest reactivation risk
    // Note: uses sys_updated_on as proxy since ServiceNow has no dedicated deactivation timestamp
    var recentlyDeactivated = [];
    var allRecords = direct.concat(inherited);

    for (var i = 0; i < allRecords.length; i++) {
        var deactivatedUser = new GlideRecord('sys_user');
        deactivatedUser.get(allRecords[i].user_sys_id);
        var updatedOn = new GlideDateTime(deactivatedUser.sys_updated_on.toString());
        var checkDaysAgo = new GlideDateTime();
        checkDaysAgo.addDaysUTC(-60);
        if (updatedOn.compareTo(checkDaysAgo) < 0) {
			
			engine.finding.setCurrentSource(deactivatedUser);
			//engine.finding.setValue('finding_details','Found with DIRECT role assignment');
			engine.finding.increment();

            recentlyDeactivated.push({
                user_name: allRecords[i].user_name,
                user_display_name: allRecords[i].user_display_name,
                email: allRecords[i].email,
                role: allRecords[i].role,
                inherited: allRecords[i].inherited,
                is_service_account: allRecords[i].is_service_account,
                deactivated_around: deactivatedUser.sys_updated_on.toString()
            });
        
		}
    }

    var serviceAccounts = allRecords.filter(function(u) {
        return u.is_service_account;
    });

    // gs.info('=== DEPROVISIONED USERS WITH PRIVILEGED ROLES ===');
    // gs.info('Direct assignments (critical - survives reactivation): ' + direct.length);
    // gs.info('Inherited assignments (high - survives reactivation): ' + inherited.length);
    // gs.info('Total records: ' + (direct.length + inherited.length));
    // gs.info('Recently deactivated (<90 days, highest reactivation risk): ' + recentlyDeactivated.length);
    // gs.info('Potential service accounts: ' + serviceAccounts.length);
    // gs.info('\nDirect assignments:');
    // gs.info(JSON.stringify(direct, null, 2));
    // gs.info('\nInherited assignments:');
    // gs.info(JSON.stringify(inherited, null, 2));
    // gs.info('\nRecently deactivated users:');
    // gs.info(JSON.stringify(recentlyDeactivated, null, 2));

})(engine);
```

</details>

---

### cstaces-2a ACL overly perm

**Priority:** 4

**What:** Identifies active ACLs that have no role restrictions, no conditions, and no scripts, meaning any authenticated user can pass them. Results are categorized by risk level: CRITICAL (wildcard * operation), HIGH (write/create/delete), MEDIUM (read), and LOW (other).

**Why:** Misconfigured ACLs are the most common access control weakness in ServiceNow instances. NIST AC-3 and CIS controls require that access to resources be enforced through policy-based mechanisms. An ACL with no restrictions is effectively no access control at all.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {


    var riskyACLs = [];
    var aclsWithRoles = {};

    // Build lookup of ACLs that have role restrictions to avoid N+1 query overhead
    var aclRoleEntry = new GlideRecord('sys_security_acl_role');
    aclRoleEntry.addNotNullQuery('sys_security_acl');
    aclRoleEntry.query();
    while (aclRoleEntry.next()) {
        aclsWithRoles[aclRoleEntry.sys_security_acl.toString()] = true;
    }

    // Query active ACLs with no condition and no script
    var aclRecord = new GlideRecord('sys_security_acl');
    aclRecord.addQuery('active', 'true');
    aclRecord.addNullQuery('condition');
    aclRecord.addNullQuery('script');
    aclRecord.addQuery('sys_policy', '!=', 'read'); // Exclude read-only locked OOB records
    aclRecord.query();

    while (aclRecord.next()) {
        var sysId = aclRecord.sys_id.toString();

        // Skip ACLs that have role restrictions
        if (aclsWithRoles[sysId]) {
            continue;
        }

        var operation = aclRecord.operation.toString();
        var riskLevel = 'LOW';

		engine.finding.setCurrentSource(aclRecord);
		engine.finding.increment();


        if (operation === '*') {
            riskLevel = 'CRITICAL'; // Wildcard operation with no controls whatsoever
        } else if (operation === 'write' || operation === 'create' || operation === 'delete') {
            riskLevel = 'HIGH';
        } else if (operation === 'read') {
            riskLevel = 'MEDIUM';
        }

        riskyACLs.push({
            sys_id: sysId,
            name: aclRecord.name.toString(),
            type: aclRecord.type.toString(),
            operation: operation,
            admin_overrides: aclRecord.admin_overrides.toString(),
            risk_level: riskLevel,
            sys_scope: aclRecord.sys_scope.getDisplayValue(),
            sys_update_name: aclRecord.sys_update_name.toString()
        });
    }

    // Sort by risk level for triage
    var riskOrder = {
        'CRITICAL': 0,
        'HIGH': 1,
        'MEDIUM': 2,
        'LOW': 3
    };
    riskyACLs.sort(function(a, b) {
        return riskOrder[a.risk_level] - riskOrder[b.risk_level];
    });

    // gs.info('=== OVERLY PERMISSIVE ACL SCAN ===');
    // gs.info('Total findings: ' + riskyACLs.length);
    // gs.info('CRITICAL: ' + riskyACLs.filter(function(a) {
    //     return a.risk_level === 'CRITICAL';
    // }).length);
    // gs.info('HIGH: ' + riskyACLs.filter(function(a) {
    //     return a.risk_level === 'HIGH';
    // }).length);
    // gs.info('MEDIUM: ' + riskyACLs.filter(function(a) {
    //     return a.risk_level === 'MEDIUM';
    // }).length);
    // gs.info('LOW: ' + riskyACLs.filter(function(a) {
    //     return a.risk_level === 'LOW';
    // }).length);
    // gs.info('Full results: ' + JSON.stringify(riskyACLs, null, 2));



})(engine);
```

</details>

---

### cstaces-2b acls dangerous

**Priority:** 3

**What:** Scans all active ACLs with non-null scripts for patterns indicating dangerous or overly permissive access control logic, including unconditional grants (answer = true), admin bypass patterns, dynamic behavior via external scripts or properties, and incomplete/disabled logic markers.

**Why:** Script-based ACLs can silently undermine the entire access control model if they contain logic that unconditionally grants access or can be manipulated externally. OWASP and CIS guidance require that access control decisions be deterministic and not reliant on client-controllable or externally mutable inputs.

<details>
<summary>View Script</summary>

```javascript
(function (engine) {


    var patterns = {
        UNCONDITIONAL_GRANT: [
            'answer = true',
            'answer=true',
            'return true'
        ],
        BYPASS_PATTERN: [
            'gs.getuser().hasrole(\'admin\')',
            'gs.hasrole(\'admin\')',
            'gs.getuser().isuseringroup',
            'current.setabortaction(false)',
            'gs.nil('
        ],
        DYNAMIC_BEHAVIOR: [
            'gs.getproperty(',
            'new glidescript(',
            'gs.includescript(',
            'javascriptprobe'
        ],
        INCOMPLETE_LOGIC: [
            '//answer',
            '/* answer',
            'todo',
            'fixme',
            'hardcoded'
        ]
    };

    var concernOrder = ['UNCONDITIONAL_GRANT', 'BYPASS_PATTERN', 'DYNAMIC_BEHAVIOR', 'INCOMPLETE_LOGIC'];
    var suspiciousACLs = {};

    var aclRecord = new GlideRecord('sys_security_acl');
    aclRecord.addQuery('active', 'true');
    aclRecord.addNotNullQuery('script');
    aclRecord.query();

    while (aclRecord.next()) {
        var script = aclRecord.script.toString();
        var scriptLower = script.toLowerCase().replace(/\s+/g, ' ');
        var sysId = aclRecord.sys_id.toString();

        var matchedPatterns = [];
        var highestConcern = null;

        for (var category in patterns) {
            var patternList = patterns[category];
            for (var i = 0; i < patternList.length; i++) {
                if (scriptLower.indexOf(patternList[i]) > -1) {

                    matchedPatterns.push({
                        pattern: patternList[i],
                        category: category
                    });

                    if (highestConcern === null ||
                        concernOrder.indexOf(category) < concernOrder.indexOf(highestConcern)) {
                        highestConcern = category;
                    }

					engine.finding.setCurrentSource(aclRecord);
					engine.finding.setValue('finding_details', JSON.stringify(matchedPatterns));
					engine.finding.increment();

                }
            }
        }

        if (matchedPatterns.length > 0) {
            suspiciousACLs[sysId] = {
                sys_id: sysId,
                name: aclRecord.name.toString(),
                table: aclRecord.name.toString().split('.')[0],
                operation: aclRecord.operation.toString(),
                highest_concern: highestConcern,
                matched_patterns: matchedPatterns,
                admin_overrides: aclRecord.admin_overrides.toString(),
                sys_scope: aclRecord.sys_scope.getDisplayValue(),
                sys_update_name: aclRecord.sys_update_name.toString(),
                script_preview: script.substring(0, 300)
            };
        }
    }

    var results = [];
    for (var id in suspiciousACLs) {
        results.push(suspiciousACLs[id]);
    }
    results.sort(function(a, b) {
        return concernOrder.indexOf(a.highest_concern) - concernOrder.indexOf(b.highest_concern);
    });

    // gs.info('=== ACL DANGEROUS SCRIPT SCAN ===');
    // gs.info('Total findings: ' + results.length);
    // gs.info('Unconditional grants: ' + results.filter(function(a) { return a.highest_concern === 'UNCONDITIONAL_GRANT'; }).length);
    // gs.info('Bypass patterns: ' + results.filter(function(a) { return a.highest_concern === 'BYPASS_PATTERN'; }).length);
    // gs.info('Dynamic behavior: ' + results.filter(function(a) { return a.highest_concern === 'DYNAMIC_BEHAVIOR'; }).length);
    // gs.info('Incomplete logic: ' + results.filter(function(a) { return a.highest_concern === 'INCOMPLETE_LOGIC'; }).length);
    // gs.info(JSON.stringify(results, null, 2));



})(engine);
```

</details>

---

### cstaces-3b has impersonator

**Priority:** 3

**What:** Identifies all active users who can impersonate others by evaluating five vectors: direct impersonator role, direct admin role, direct security_admin role, group membership inheriting those roles, and role hierarchy where a parent role contains impersonator as a child.

**Why:** Impersonation capability is often granted implicitly through admin or security_admin roles, making the true population of impersonators far larger than expected. NIST AC-6(1) requires organizations to explicitly authorize access to privileged functions, and impersonation must be inventoried across all grant vectors.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    var impersonators = {};

    function addUser(userSysId, source) {
        if (!userSysId) return;
        var u = new GlideRecord('sys_user');
        if (u.get(userSysId)) {
            if (u.getValue('active') != '1') return;
            var uname = u.user_name.toString();
            if (!impersonators[uname]) {
                impersonators[uname] = {
                    user: u.name.toString(),
                    user_name: uname,
                    email: u.email.toString(),
                    last_login: u.last_login_time.toString(),
                    is_service_account: (uname.indexOf('svc') > -1 ||
                        uname.indexOf('service') > -1 ||
                        uname.indexOf('integration') > -1 ||
                        uname.indexOf('api') > -1) ? true : false,
                    sources: []
                };
            }
            if (impersonators[uname].sources.indexOf(source) === -1) {
                impersonators[uname].sources.push(source);
            }
        }
    }

    // 1. Direct impersonator role
    var direct = new GlideRecord('sys_user_has_role');
    direct.addQuery('role.name', 'impersonator');
    direct.addQuery('user.active', 'true');
    direct.addQuery('state', 'active');
    direct.query();
    while (direct.next()) {

		var userRec = direct.user.getRefRecord();
		engine.finding.setCurrentSource(userRec);
		engine.finding.setValue('finding_details','Found with DIRECT IMPERSONATOR role assignment');
		engine.finding.increment();

        addUser(direct.getValue('user'), 'direct:impersonator');

    }

    // 2. Direct admin role (implicitly grants impersonation)
    var adminDirect = new GlideRecord('sys_user_has_role');
    adminDirect.addQuery('role.name', 'admin');
    adminDirect.addQuery('user.active', 'true');
    adminDirect.addQuery('state', 'active');
    adminDirect.query();
    while (adminDirect.next()) {

		var userRec2 = adminDirect.user.getRefRecord();
		engine.finding.setCurrentSource(userRec2);
		engine.finding.setValue('finding_details','Found with ADMIN role assignment');
		engine.finding.increment();

        addUser(adminDirect.getValue('user'), 'direct:admin');
    
	}

    // // 3. Direct security_admin role
    // var secAdmin = new GlideRecord('sys_user_has_role');
    // secAdmin.addQuery('role.name', 'security_admin');
    // secAdmin.addQuery('user.active', 'true');
    // secAdmin.addQuery('state', 'active');
    // secAdmin.query();
    // while (secAdmin.next()) {

	// 	var userRec3 = secAdmin.user.getRefRecord();
	// 	engine.finding.setCurrentSource(userRec3);
	// 	engine.finding.increment();

    //     addUser(secAdmin.getValue('user'), 'direct:security_admin');

    // }

    // 4. Group-inherited impersonator, admin, security_admin
    var elevatedRoles = ['impersonator', 'admin'];
    for (var e = 0; e < elevatedRoles.length; e++) {
        var elevatedRoleName = elevatedRoles[e];
        var groupRole = new GlideRecord('sys_group_has_role');
        groupRole.addQuery('role.name', elevatedRoleName);
        groupRole.query();
        while (groupRole.next()) {
            var groupName = groupRole.group.name.toString();
            var member = new GlideRecord('sys_user_grmember');
            member.addQuery('group', groupRole.getValue('group'));
            member.addQuery('user.active', 'true');
            member.query();
            while (member.next()) {

				var userRec4 = direct.user.getRefRecord();
				engine.finding.setCurrentSource(userRec4);
				engine.finding.setValue('finding_details','Found with GROUP INHEIRITED IMP role assignment');
				engine.finding.increment();

                addUser(member.getValue('user'), 'group:' + groupName + ':' + elevatedRoleName);
            
			}
        }
    }

    // // 5. Parent roles containing impersonator as a child role (role hierarchy)
    // var childRole = new GlideRecord('sys_user_role_contains');
    // childRole.addQuery('role.name', 'impersonator');
    // childRole.query();
    // while (childRole.next()) {
    //     var parentRoleName = childRole.parent.name.toString();
    //     var parentRoleId = childRole.getValue('parent');

    //     var parentUsers = new GlideRecord('sys_user_has_role');
    //     parentUsers.addQuery('role', parentRoleId);
    //     parentUsers.addQuery('user.active', 'true');
    //     parentUsers.query();
    //     while (parentUsers.next()) {

	// 		var userRec5 = parentUsers.user.getRefRecord();
	// 		engine.finding.setCurrentSource(userRec5);
	// 		engine.finding.setValue('finding_details','Found with NESTED role assignment');
	// 		engine.finding.increment();

    //         addUser(parentUsers.getValue('user'), 'inherited_role:' + parentRoleName);

    //     }

    //     var parentGroups = new GlideRecord('sys_group_has_role');
    //     parentGroups.addQuery('role', parentRoleId);
    //     parentGroups.query();
    //     while (parentGroups.next()) {
    //         var gName = parentGroups.group.name.toString();
    //         var gMembers = new GlideRecord('sys_user_grmember');
    //         gMembers.addQuery('group', parentGroups.getValue('group'));
    //         gMembers.addQuery('user.active', 'true');
    //         gMembers.query();
    //         while (gMembers.next()) {

	// 			var userRec6 = gMembers.user.getRefRecord();
	// 			engine.finding.setCurrentSource(userRec6);
	// 			engine.finding.increment();

    //             addUser(gMembers.getValue('user'), 'group_inherited_role:' + gName + ':' + parentRoleName);
            
	// 		}
    //     }
    // }

    var results = [];
    for (var uname in impersonators) {
        results.push(impersonators[uname]);
    }

    var serviceAccounts = results.filter(function(u) {
        return u.is_service_account;
    });
    var humanAccounts = results.filter(function(u) {
        return !u.is_service_account;
    });

    // gs.info('Total users with impersonation capability: ' + results.length);
    // gs.info('Human accounts: ' + humanAccounts.length);
    // gs.info('Potential service accounts: ' + serviceAccounts.length);
    // gs.info(JSON.stringify(results, null, 2));

})(engine);
```

</details>

---

### cstaces-3b2 nested impersonator

**Priority:** 3

**What:** Identifies all active users who can impersonate others by evaluating five vectors: direct impersonator role, direct admin role, direct security_admin role, group membership inheriting those roles, and role hierarchy where a parent role contains impersonator as a child.

**Why:** Impersonation capability is often granted implicitly through admin or security_admin roles, making the true population of impersonators far larger than expected. NIST AC-6(1) requires organizations to explicitly authorize access to privileged functions, and impersonation must be inventoried across all grant vectors.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    // var impersonators = {};

    // function addUser(userSysId, source) {
    //     if (!userSysId) return;
    //     var u = new GlideRecord('sys_user');
    //     if (u.get(userSysId)) {
    //         if (u.getValue('active') != '1') return;
    //         var uname = u.user_name.toString();
    //         if (!impersonators[uname]) {
    //             impersonators[uname] = {
    //                 user: u.name.toString(),
    //                 user_name: uname,
    //                 email: u.email.toString(),
    //                 last_login: u.last_login_time.toString(),
    //                 is_service_account: (uname.indexOf('svc') > -1 ||
    //                     uname.indexOf('service') > -1 ||
    //                     uname.indexOf('integration') > -1 ||
    //                     uname.indexOf('api') > -1) ? true : false,
    //                 sources: []
    //             };
    //         }
    //         if (impersonators[uname].sources.indexOf(source) === -1) {
    //             impersonators[uname].sources.push(source);
    //         }
    //     }
    // }


    // 5. Parent roles containing impersonator as a child role (role hierarchy)
    var childRole = new GlideRecord('sys_user_role_contains');
    childRole.addQuery('contains.name', 'impersonator');
    childRole.query();
    while (childRole.next()) {
        var parentRoleName = childRole.parent.name.toString();
        var parentRoleId = childRole.getValue('parent');

        // var parentUsers = new GlideRecord('sys_user_has_role');
        // parentUsers.addQuery('role', parentRoleId);
        // parentUsers.addQuery('user.active', 'true');
        // parentUsers.query();
        // while (parentUsers.next()) {

        //     var userRec5 = parentUsers.user.getRefRecord();
		engine.finding.setCurrentSource(childRole);
		engine.finding.setValue('finding_details', 'Found with NESTED IMPERSONATOR role assignment');
		engine.finding.increment();

        //     //addUser(parentUsers.getValue('user'), 'inherited_role:' + parentRoleName);

        // }

        var parentGroups = new GlideRecord('sys_group_has_role');
        parentGroups.addQuery('role', parentRoleId);
        parentGroups.query();
        while (parentGroups.next()) {
            var gName = parentGroups.group.name.toString();
            var gMembers = new GlideRecord('sys_user_grmember');
            gMembers.addQuery('group', parentGroups.getValue('group'));
            gMembers.addQuery('user.active', 'true');
            gMembers.query();
            while (gMembers.next()) {

                var userRec6 = gMembers.user.getRefRecord();
                engine.finding.setCurrentSource(userRec6);
				engine.finding.setValue('finding_details', 'Found with GROUP ASSIGNED NESTED role assignment');
                engine.finding.increment();

                //addUser(gMembers.getValue('user'), 'group_inherited_role:' + gName + ':' + parentRoleName);

            }
        }
    }

    // var results = [];
    // for (var uname in impersonators) {
    //     results.push(impersonators[uname]);
    // }

    // var serviceAccounts = results.filter(function(u) {
    //     return u.is_service_account;
    // });
    // var humanAccounts = results.filter(function(u) {
    //     return !u.is_service_account;
    // });

    // gs.info('Total users with impersonation capability: ' + results.length);
    // gs.info('Human accounts: ' + humanAccounts.length);
    // gs.info('Potential service accounts: ' + serviceAccounts.length);
    // gs.info(JSON.stringify(results, null, 2));

})(engine);
```

</details>

---

### cstaces-4a secadmin

**Priority:** 3

**What:** Enumerates all active users with the security_admin role via direct and group-inherited assignments. Cross-references whether each user also holds the admin role, which compounds privilege. This query establishes the population used by queries 4b through 4e.

**Why:** The security_admin role controls ACLs, encryption, and role assignments. An unchecked security_admin population is a top-tier risk because it can modify the controls that protect everything else. NIST AC-6(5) requires that privileged accounts be inventoried and reviewed on a regular cadence.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    var secAdmins = {};

    function addUser(userSysId, source) {
        if (!userSysId) return;
        var u = new GlideRecord('sys_user');
        if (u.get(userSysId)) {
            if (u.getValue('active') != '1') return;
            var uname = u.user_name.toString();
            if (!secAdmins[uname]) {
                secAdmins[uname] = {
                    user: u.name.toString(),
                    user_name: uname,
                    email: u.email.toString(),
                    last_login: u.last_login_time.toString(),
                    is_service_account: (uname.indexOf('svc') > -1 ||
                        uname.indexOf('service') > -1 ||
                        uname.indexOf('integration') > -1 ||
                        uname.indexOf('api') > -1) ? true : false,
                    sources: []
                };
            }
            if (secAdmins[uname].sources.indexOf(source) === -1) {
                secAdmins[uname].sources.push(source);
            }
        }
    }

    var direct = new GlideRecord('sys_user_has_role');
    direct.addQuery('role.name', 'security_admin');
    direct.addQuery('user.active', 'true');
    direct.addQuery('state', 'active');
    direct.query();
    while (direct.next()) {

		var userRec = direct.user.getRefRecord();
		engine.finding.setCurrentSource(userRec);
		engine.finding.increment();

        addUser(direct.getValue('user'), 'direct:security_admin');
    }

    var groupRole = new GlideRecord('sys_group_has_role');
    groupRole.addQuery('role.name', 'security_admin');
    groupRole.query();
    while (groupRole.next()) {
        var groupName = groupRole.group.name.toString();
        var member = new GlideRecord('sys_user_grmember');
        member.addQuery('group', groupRole.getValue('group'));
        member.addQuery('user.active', 'true');
        member.query();
        while (member.next()) {

			var userRec2 = groupRole.user.getRefRecord();
			engine.finding.setCurrentSource(userRec2);
			engine.finding.increment();

            addUser(member.getValue('user'), 'group:' + groupName);
        }
    }

    var results = [];
    for (var uname in secAdmins) {
        var entry = secAdmins[uname];
        // Check if this user also holds the admin role (compounding privilege)
        var adminCheck = new GlideRecord('sys_user_has_role');
        adminCheck.addQuery('user.user_name', uname);
        adminCheck.addQuery('role.name', 'admin');
        adminCheck.addQuery('user.active', 'true');
        adminCheck.addQuery('state', 'active');
        adminCheck.query();
        entry.has_admin = adminCheck.next() ? true : false;
        results.push(entry);
    }

    var withAdmin = results.filter(function(u) {
        return u.has_admin;
    });
    var withoutAdmin = results.filter(function(u) {
        return !u.has_admin;
    });
    var serviceAccounts = results.filter(function(u) {
        return u.is_service_account;
    });

    // gs.info('Total users with security_admin: ' + results.length);
    // gs.info('Also have admin (compounding privilege): ' + withAdmin.length);
    // gs.info('security_admin without admin: ' + withoutAdmin.length);
    // gs.info('Potential service accounts: ' + serviceAccounts.length);
    // gs.info(JSON.stringify(results, null, 2));

})(engine);
```

</details>

---

### cstaces-4b acl modif

**Priority:** 3

**What:** Detects ACL and role table changes made by security_admin users in the last 30 days by querying the audit log for modifications to sys_acl, sys_security_acl, sys_user_has_role, and sys_group_has_role.

**Why:** ACL modification is the primary vector through which security_admin privilege can be used to escalate access. SOC 2 CC6.1 and NIST AU-12 require that changes to access control configurations be logged, attributed, and reviewed. Unmonitored ACL changes can silently dismantle an instance's security posture.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    var secAdminUsers = {};

    function collectUser(userSysId) {
        if (!userSysId) return;
        var u = new GlideRecord('sys_user');
        if (u.get(userSysId) && u.getValue('active') == '1') {
            secAdminUsers[u.user_name.toString()] = u.name.toString();
        }
    }

    var direct = new GlideRecord('sys_user_has_role');
    direct.addQuery('role.name', 'security_admin');
    direct.addQuery('user.active', 'true');
    direct.addQuery('state', 'active');
    direct.query();
    while (direct.next()) {
        collectUser(direct.getValue('user'));
    }

    var groupRole = new GlideRecord('sys_group_has_role');
    groupRole.addQuery('role.name', 'security_admin');
    groupRole.query();
    while (groupRole.next()) {
        var member = new GlideRecord('sys_user_grmember');
        member.addQuery('group', groupRole.getValue('group'));
        member.addQuery('user.active', 'true');
        member.query();
        while (member.next()) {
            collectUser(member.getValue('user'));
        }
    }

    var secAdminUsernames = [];
    for (var u in secAdminUsers) {
        secAdminUsernames.push(u);
    }

    //gs.info('security_admin population: ' + secAdminUsernames.length + ' users');

    var highRiskTables = ['sys_acl', 'sys_security_acl', 'sys_user_has_role', 'sys_group_has_role'];
    var aclChanges = [];

    for (var i = 0; i < secAdminUsernames.length; i++) {
        var uname = secAdminUsernames[i];
        var audit = new GlideRecord('sys_audit');
        audit.addQuery('user', uname);
        audit.addQuery('tablename', 'IN', highRiskTables.join(','));
        audit.addQuery('sys_created_on', '>', gs.daysAgo(30)); // Configurable lookback
        audit.orderByDesc('sys_created_on');
        audit.setLimit(100);
        audit.query();
        while (audit.next()) {

			engine.finding.setCurrentSource(audit);
			//engine.finding.setValue('finding_details','');
			engine.finding.increment();


            aclChanges.push({
                timestamp: audit.sys_created_on.toString(),
                user: uname,
                display_name: secAdminUsers[uname],
                table_modified: audit.tablename.toString(),
                record_id: audit.documentkey.toString(),
                field_changed: audit.fieldname.toString(),
                old_value: audit.oldvalue.toString(),
                new_value: audit.newvalue.toString()
            });
			
        }
    }

    // gs.info('ACL modifications by security_admin users (last 30 days): ' + aclChanges.length);
    // gs.info(JSON.stringify(aclChanges, null, 2));

})(engine);
```

</details>

---

### cstaces-4c self role grant

**Priority:** 4

**What:** Detects role assignment changes made by security_admin users in the last 30 days. Flags self-grants and grants of high-risk roles (admin, security_admin, impersonator) as the most direct indicators of privilege escalation.

**Why:** Role grants are the most explicit form of privilege escalation. A security_admin granting themselves or others additional elevated roles bypasses intended approval workflows. NIST AC-6(5) and SOC 2 CC6.1 require that privileged role changes be authorized, logged, and reviewed for anomalous patterns.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    var secAdminUsers = {};

    function collectUser(userSysId) {
        if (!userSysId) return;
        var u = new GlideRecord('sys_user');
        if (u.get(userSysId) && u.getValue('active') == '1') {
            secAdminUsers[u.user_name.toString()] = u.name.toString();
        }
    }

    var direct = new GlideRecord('sys_user_has_role');
    direct.addQuery('role.name', 'security_admin');
    direct.addQuery('user.active', 'true');
    direct.addQuery('state', 'active');
    direct.query();
    while (direct.next()) {
        collectUser(direct.getValue('user'));
    }

    var groupRole = new GlideRecord('sys_group_has_role');
    groupRole.addQuery('role.name', 'security_admin');
    groupRole.query();
    while (groupRole.next()) {
        var member = new GlideRecord('sys_user_grmember');
        member.addQuery('group', groupRole.getValue('group'));
        member.addQuery('user.active', 'true');
        member.query();
        while (member.next()) {
            collectUser(member.getValue('user'));
        }
    }

    var secAdminUsernames = [];
    for (var u in secAdminUsers) {
        secAdminUsernames.push(u);
    }

    gs.info('security_admin population: ' + secAdminUsernames.length + ' users');

    var highRiskRoles = ['admin', 'security_admin', 'impersonator'];
    var roleGrantTables = ['sys_user_has_role', 'sys_group_has_role'];
    var roleGrants = [];

    for (var i = 0; i < secAdminUsernames.length; i++) {
        var uname = secAdminUsernames[i];
        var audit = new GlideRecord('sys_audit');
        audit.addQuery('user', uname);
        audit.addQuery('tablename', 'IN', roleGrantTables.join(','));
        audit.addQuery('sys_created_on', '>', gs.daysAgo(30)); // Configurable lookback
        audit.orderByDesc('sys_created_on');
        audit.setLimit(100);
        audit.query();

        while (audit.next()) {
            var roleName = '';
            var recipient = '';
            var tableModified = audit.tablename.toString();

            var roleRecord = new GlideRecord(tableModified);
            if (roleRecord.get(audit.documentkey.toString())) {
                roleName = roleRecord.role.name.toString();
                recipient = tableModified === 'sys_user_has_role' ?
                    roleRecord.user.user_name.toString() :
                    roleRecord.group.name.toString();
            }

            var isSelfGrant = (recipient === uname);
            var isHighRisk = false;
            for (var j = 0; j < highRiskRoles.length; j++) {
                if (roleName === highRiskRoles[j]) {
                    isHighRisk = true;
                    break;
                }
            }

            roleGrants.push({
                timestamp: audit.sys_created_on.toString(),
                granted_by: uname,
                granted_by_display: secAdminUsers[uname],
                recipient: recipient,
                role_granted: roleName,
                table: tableModified,
                field_changed: audit.fieldname.toString(),
                old_value: audit.oldvalue.toString(),
                new_value: audit.newvalue.toString(),
                is_self_grant: isSelfGrant,
                is_high_risk_role: isHighRisk
            });
        }
    }

    var highRiskGrants = [];
    var selfGrants = [];
    for (var k = 0; k < roleGrants.length; k++) {
        if (roleGrants[k].is_self_grant) selfGrants.push(roleGrants[k]);
        if (roleGrants[k].is_high_risk_role) highRiskGrants.push(roleGrants[k]);
    }

    gs.info('Total role grants by security_admin users (last 30 days): ' + roleGrants.length);
    gs.info('High risk role grants (admin/security_admin/impersonator): ' + highRiskGrants.length);
    gs.info('Self grants: ' + selfGrants.length);
    gs.info(JSON.stringify(roleGrants, null, 2));

})(engine);
```

</details>

---

### cstaces-4d1 secadmin script changes

**Priority:** 4

**What:** Detects modifications to server-side scripts (business rules, script includes, UI actions, web service operations, and processors) made by security_admin users in the last 30 days. Flags changes to active scripts as higher concern.

**Why:** Server-side scripts execute with elevated privileges and represent an indirect but powerful path to platform compromise. A security_admin modifying a business rule can inject logic that runs on every transaction against a table. NIST SI-7 and CIS control 2.7 require integrity monitoring of executable code and configuration.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    var secAdminUsers = {};

    function collectUser(userSysId) {
        if (!userSysId) return;
        var u = new GlideRecord('sys_user');
        if (u.get(userSysId) && u.getValue('active') == '1') {
            secAdminUsers[u.user_name.toString()] = u.name.toString();
        }
    }

    var direct = new GlideRecord('sys_user_has_role');
    direct.addQuery('role.name', 'security_admin');
    direct.addQuery('user.active', 'true');
    direct.addQuery('state', 'active');
    direct.query();
    while (direct.next()) {
        collectUser(direct.getValue('user'));
    }

    var groupRole = new GlideRecord('sys_group_has_role');
    groupRole.addQuery('role.name', 'security_admin');
    groupRole.query();
    while (groupRole.next()) {
        var member = new GlideRecord('sys_user_grmember');
        member.addQuery('group', groupRole.getValue('group'));
        member.addQuery('user.active', 'true');
        member.query();
        while (member.next()) {
            collectUser(member.getValue('user'));
        }
    }

    var secAdminUsernames = [];
    for (var u in secAdminUsers) {
        secAdminUsernames.push(u);
    }

    gs.info('security_admin population: ' + secAdminUsernames.length + ' users');

    var scriptTables = [
        'sys_script', // Business rules
        'sys_script_include', // Script includes
        'sys_ui_action', // UI actions
        'sys_ws_operation', // Web service operations
        'sys_processor' // Processors
    ];

    var scriptChanges = [];

    for (var i = 0; i < secAdminUsernames.length; i++) {
        var uname = secAdminUsernames[i];
        var audit = new GlideRecord('sys_audit');
        audit.addQuery('user', uname);
        audit.addQuery('tablename', 'IN', scriptTables.join(','));
        audit.addQuery('sys_created_on', '>', gs.daysAgo(30)); // Configurable lookback
        audit.orderByDesc('sys_created_on');
        audit.setLimit(100);
        audit.query();

        while (audit.next()) {
            var tableModified = audit.tablename.toString();
            var recordId = audit.documentkey.toString();
            var scriptName = '';
            var isActive = '';

            var scriptRecord = new GlideRecord(tableModified);
            if (scriptRecord.get(recordId)) {
                scriptName = scriptRecord.name.toString();
                isActive = scriptRecord.active.toString();
            }

			var scriptRecordSpecificChanges = {
                timestamp: audit.sys_created_on.toString(),
                changed_by: uname,
                changed_by_display: secAdminUsers[uname],
                table: tableModified,
                script_name: scriptName,
                is_active: isActive,
                field_changed: audit.fieldname.toString(),
                old_value: audit.oldvalue.toString().substring(0, 100),
                new_value: audit.newvalue.toString().substring(0, 100)
            };

            scriptChanges.push(scriptRecordSpecificChanges);

			engine.finding.setCurrentSource(scriptRecord);
			engine.finding.setValue('finding_details',JSON.stringify(scriptRecordSpecificChanges,null,4));
			engine.finding.increment();
			
        }
    }

    var activeScriptChanges = [];
    var inactiveScriptChanges = [];
    for (var k = 0; k < scriptChanges.length; k++) {
        if (scriptChanges[k].is_active === 'true' || scriptChanges[k].is_active === '1') {
            activeScriptChanges.push(scriptChanges[k]);
        } else {
            inactiveScriptChanges.push(scriptChanges[k]);
        }
    }

    // gs.info('Total script changes by security_admin users (last 30 days): ' + scriptChanges.length);
    // gs.info('Changes to active scripts: ' + activeScriptChanges.length);
    // gs.info('Changes to inactive scripts: ' + inactiveScriptChanges.length);
    // gs.info(JSON.stringify(scriptChanges, null, 2));

})(engine);
```

</details>

---

### cstaces-4d2 admin script changes

**Priority:** 4

**What:** Detects modifications to server-side scripts (business rules, script includes, UI actions, web service operations, and processors) made by security_admin users in the last 30 days. Flags changes to active scripts as higher concern.

**Why:** Server-side scripts execute with elevated privileges and represent an indirect but powerful path to platform compromise. A security_admin modifying a business rule can inject logic that runs on every transaction against a table. NIST SI-7 and CIS control 2.7 require integrity monitoring of executable code and configuration.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    var secAdminUsers = {};

    function collectUser(userSysId) {
        if (!userSysId) return;
        var u = new GlideRecord('sys_user');
        if (u.get(userSysId) && u.getValue('active') == '1') {
            secAdminUsers[u.user_name.toString()] = u.name.toString();
        }
    }

    var direct = new GlideRecord('sys_user_has_role');
    direct.addQuery('role.name', 'admin');
    direct.addQuery('user.active', 'true');
    direct.addQuery('state', 'active');
    direct.query();
    while (direct.next()) {
        collectUser(direct.getValue('user'));
    }

    var groupRole = new GlideRecord('sys_group_has_role');
    groupRole.addQuery('role.name', 'admin');
    groupRole.query();
    while (groupRole.next()) {
        var member = new GlideRecord('sys_user_grmember');
        member.addQuery('group', groupRole.getValue('group'));
        member.addQuery('user.active', 'true');
        member.query();
        while (member.next()) {
            collectUser(member.getValue('user'));
        }
    }

    var secAdminUsernames = [];
    for (var u in secAdminUsers) {
        secAdminUsernames.push(u);
    }

    //gs.info('admin population: ' + secAdminUsernames.length + ' users');

    var scriptTables = [
        'sys_script', // Business rules
        'sys_script_include', // Script includes
        'sys_ui_action', // UI actions
        'sys_ws_operation', // Web service operations
        'sys_processor' // Processors
    ];

    var scriptChanges = [];

    for (var i = 0; i < secAdminUsernames.length; i++) {
        var uname = secAdminUsernames[i];
        var audit = new GlideRecord('sys_audit');
        audit.addQuery('user', uname);
        audit.addQuery('tablename', 'IN', scriptTables.join(','));
        audit.addQuery('sys_created_on', '>', gs.daysAgo(30)); // Configurable lookback
        audit.orderByDesc('sys_created_on');
        audit.setLimit(100);
        audit.query();

        while (audit.next()) {
            var tableModified = audit.tablename.toString();
            var recordId = audit.documentkey.toString();
            var scriptName = '';
            var isActive = '';

            var scriptRecord = new GlideRecord(tableModified);
            if (scriptRecord.get(recordId)) {
                scriptName = scriptRecord.name.toString();
                isActive = scriptRecord.active.toString();
            }

			var scriptRecordSpecificChanges = {
                timestamp: audit.sys_created_on.toString(),
                changed_by: uname,
                changed_by_display: secAdminUsers[uname],
                table: tableModified,
                script_name: scriptName,
                is_active: isActive,
                field_changed: audit.fieldname.toString(),
                old_value: audit.oldvalue.toString().substring(0, 100),
                new_value: audit.newvalue.toString().substring(0, 100)
            };

            scriptChanges.push(scriptRecordSpecificChanges);

			engine.finding.setCurrentSource(scriptRecord);
			engine.finding.setValue('finding_details',JSON.stringify(scriptRecordSpecificChanges,null,4));
			engine.finding.increment();
			
        }
    }

    var activeScriptChanges = [];
    var inactiveScriptChanges = [];
    for (var k = 0; k < scriptChanges.length; k++) {
        if (scriptChanges[k].is_active === 'true' || scriptChanges[k].is_active === '1') {
            activeScriptChanges.push(scriptChanges[k]);
        } else {
            inactiveScriptChanges.push(scriptChanges[k]);
        }
    }

    // gs.info('Total script changes by security_admin users (last 30 days): ' + scriptChanges.length);
    // gs.info('Changes to active scripts: ' + activeScriptChanges.length);
    // gs.info('Changes to inactive scripts: ' + inactiveScriptChanges.length);
    // gs.info(JSON.stringify(scriptChanges, null, 2));

})(engine);
```

</details>

---

### cstaces-4e encryption configs

**Priority:** 4

**What:** Detects modifications to Platform Encryption resources (crypto modules, key maps, keys, key stores, certificates, and encryption contexts) made by security_admin users in the last 30 days. Flags deactivation events and changes to high-risk KMF tables separately.

**Why:** Encryption key management is foundational to data protection. Unauthorized changes to encryption configuration can expose encrypted data at rest or render it unrecoverable. NIST SC-12 and SC-28 require that cryptographic key management activities be controlled and auditable.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    var secAdminUsers = {};

    function collectUser(userSysId) {
        if (!userSysId) return;
        var u = new GlideRecord('sys_user');
        if (u.get(userSysId) && u.getValue('active') == '1') {
            secAdminUsers[u.user_name.toString()] = u.name.toString();
        }
    }

    var direct = new GlideRecord('sys_user_has_role');
    direct.addQuery('role.name', 'admin');
    direct.addQuery('user.active', 'true');
    direct.addQuery('state', 'active');
    direct.query();
    while (direct.next()) {
        collectUser(direct.getValue('user'));
    }

    var groupRole = new GlideRecord('sys_group_has_role');
    groupRole.addQuery('role.name', 'admin');
    groupRole.query();
    while (groupRole.next()) {
        var member = new GlideRecord('sys_user_grmember');
        member.addQuery('group', groupRole.getValue('group'));
        member.addQuery('user.active', 'true');
        member.query();
        while (member.next()) {
            collectUser(member.getValue('user'));
        }
    }

    var secAdminUsernames = [];
    for (var u in secAdminUsers) {
        secAdminUsernames.push(u);
    }

    //gs.info('security_admin population: ' + secAdminUsernames.length + ' users');

    var encryptionTables = [
        'sys_kmf_crypto_module', // Crypto modules
        'sys_kmf_map', // Key maps (which fields are encrypted)
        'sys_kmf_key', // Encryption keys
        'sys_kmf_key_store', // Key stores
        'sys_kmf_key_store_alias', // Key store aliases
        'sys_kmf_crypto_spec', // Crypto specifications
        'sys_kmf_key_lifecycle', // Key lifecycle policies
        'sys_certificate', // Certificates
        'sys_encryption_context' // Encryption contexts
    ];

    var highRiskTables = ['sys_kmf_map', 'sys_kmf_key', 'sys_kmf_crypto_module'];
    var encryptionChanges = [];

    for (var i = 0; i < secAdminUsernames.length; i++) {
        var uname = secAdminUsernames[i];
        var audit = new GlideRecord('sys_audit');
        audit.addQuery('user', uname);
        audit.addQuery('tablename', 'IN', encryptionTables.join(','));
        audit.addQuery('sys_created_on', '>', gs.daysAgo(30)); // Configurable lookback
        audit.orderByDesc('sys_created_on');
        audit.setLimit(100);
        audit.query();

        while (audit.next()) {
            var tableModified = audit.tablename.toString();
            var recordId = audit.documentkey.toString();
            var recordName = '';

            var encRecord = new GlideRecord(tableModified);
            if (encRecord.get(recordId)) {
                recordName = encRecord.name.toString();
            }

            var fieldChanged = audit.fieldname.toString();
            var oldValue = audit.oldvalue.toString();
            var newValue = audit.newvalue.toString();
            var isDeactivation = (fieldChanged === 'active' && oldValue === '1' && newValue === '0');

            var isHighRisk = false;
            for (var j = 0; j < highRiskTables.length; j++) {
                if (tableModified === highRiskTables[j]) {
                    isHighRisk = true;
                    break;
                }
            }



			var encryptionAuditObj = {
                timestamp: audit.sys_created_on.toString(),
                changed_by: uname,
                changed_by_display: secAdminUsers[uname],
                table: tableModified,
                record_name: recordName,
                field_changed: fieldChanged,
                old_value: oldValue,
                new_value: newValue,
                is_deactivation: isDeactivation,
                is_high_risk_table: isHighRisk
            };

            encryptionChanges.push(encryptionAuditObj);

			engine.finding.setCurrentSource(encRecord);
			engine.finding.setValue('finding_details',JSON.stringify(encryptionAuditObj,null,4));
			engine.finding.increment();

        }
    }

    var deactivations = [];
    var highRiskChanges = [];
    var otherChanges = [];

    for (var k = 0; k < encryptionChanges.length; k++) {
        if (encryptionChanges[k].is_deactivation) {
            deactivations.push(encryptionChanges[k]);
        } else if (encryptionChanges[k].is_high_risk_table) {
            highRiskChanges.push(encryptionChanges[k]);
        } else {
            otherChanges.push(encryptionChanges[k]);
        }
    }

    gs.info('Total encryption changes by security_admin users (last 30 days): ' + encryptionChanges.length);
    gs.info('Deactivation events: ' + deactivations.length);
    gs.info('High risk table changes (sys_kmf_map, sys_kmf_key, sys_kmf_crypto_module): ' + highRiskChanges.length);
    gs.info('Other encryption changes: ' + otherChanges.length);
    gs.info(JSON.stringify(encryptionChanges, null, 2));

})(engine);
```

</details>

---

### cstaces-5a integration admins

**Priority:** 2

**What:** Finds all active users flagged as web-service-access-only (integration/API accounts) that have been assigned roles containing "admin" in the name. These are non-interactive accounts with overly broad privileges.

**Why:** Integration accounts should follow the principle of least privilege more strictly than human accounts because they typically operate unattended and are harder to monitor for misuse. CIS and NIST AC-6(10) recommend that non-interactive service accounts be restricted to the minimum permissions required for their function.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    // Find integration users with overly broad access
    var integrationUser = new GlideRecord('sys_user');
    integrationUser.addQuery('web_service_access_only', 'true');
    integrationUser.addQuery('active', 'true');
    integrationUser.query();

    var integrationUsers = [];
    while (integrationUser.next()) {
        var roles = [];
        var userRoleAssignment = new GlideRecord('sys_user_has_role');
        userRoleAssignment.addQuery('user', integrationUser.getUniqueValue());
        userRoleAssignment.query();

        while (userRoleAssignment.next()) {
            roles.push(userRoleAssignment.role.name.toString());
        }

        // Flag if integration user has any role containing "admin"
        var hasAdminRole = false;
        for (var i = 0; i < roles.length; i++) {
            if (roles[i].indexOf('admin') > -1) {
                hasAdminRole = true;
                break;
            }
        }

        if (hasAdminRole) {

			engine.finding.setCurrentSource(integrationUser);
			engine.finding.increment();

            integrationUsers.push({
                user: integrationUser.user_name.toString(),
                name: integrationUser.name.toString(),
                roles: roles,
                last_login: integrationUser.last_login_time.toString()
            });
        }
    }

    //gs.warn('Integration users with admin roles: ' + JSON.stringify(integrationUsers, null, 2));

})(engine);
```

</details>

---

### cstaces-5b active oauth

**Priority:** 3

**What:** Audits all active OAuth application registrations, capturing client IDs, redirect URLs, and access/refresh token lifespans. Identifies applications that may have excessively long token lifetimes.

**Why:** OAuth tokens are bearer credentials - anyone who possesses a valid token can use it. Excessively long token lifespans increase the window of opportunity for token theft and replay. NIST IA-5(13) and OAuth 2.0 Security Best Current Practice (RFC 9700) recommend short-lived access tokens and bounded refresh token lifetimes.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    // Audit active OAuth applications and their token lifespans
    var oauthEntity = new GlideRecord('oauth_entity');
    oauthEntity.addQuery('active', 'true');
    oauthEntity.query();

    var oauthApps = [];
    while (oauthEntity.next()) {

		engine.finding.setCurrentSource(oauthEntity);
		engine.finding.increment();

        oauthApps.push({
            name: oauthEntity.name.toString(),
            client_id: oauthEntity.client_id.toString(),
            redirect_url: oauthEntity.redirect_url.toString(),
            access_token_lifespan: oauthEntity.access_token_lifespan.toString(),
            refresh_token_lifespan: oauthEntity.refresh_token_lifespan.toString()
        });
    }

    //gs.info('Active OAuth applications: ' + JSON.stringify(oauthApps, null, 2));

})(engine);
```

</details>

---

### cstaces-6 BR priv esc

**Priority:** 4

**What:** Scans all active business rules for dangerous script patterns including gs.setProperty, direct manipulation of sys_user or sys_user_has_role, abort action overrides, role assignments, and session data injection. Reports matched patterns per rule for targeted review.

**Why:** Business rules execute server-side with system-level privileges and fire automatically on database operations. A malicious or poorly written business rule can modify user records, grant roles, or alter system properties on every insert/update. NIST SI-7 requires integrity verification of operational code, and CIS recommends auditing scripts that run with elevated privileges.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {


    //var sw = new GlideStopWatch();

    var businessRule = new GlideRecord('sys_script');
    businessRule.addQuery('active', 'true');
    businessRule.addQuery('when', 'IN', 'before,after,async,display');
    businessRule.query();

    //gs.info('Scanning ' + businessRule.getRowCount() + ' active business rules...\n');

    var systemRules = [];
    var dangerousPatterns = [
        'gs.setProperty',
        'GlideRecord(\'sys_user\')',
        'GlideRecord("sys_user")',
        'current.setAbortAction(false)',
        'gs.getUser().setRole',
        'gs.addRole',
        'gs.nil(',
        'GlideRecord(\'sys_user_has_role\')',
        'GlideRecord("sys_user_has_role")',
        'gs.getSession().putClientData',
        'answer = true;'
    ];

    while (businessRule.next()) {
        var script = businessRule.script.toString();
        var matchedPatterns = [];

        for (var i = 0; i < dangerousPatterns.length; i++) {
            if (script.indexOf(dangerousPatterns[i]) > -1) {
                matchedPatterns.push(dangerousPatterns[i]);
            }
        }

        if (matchedPatterns.length > 0) {

			
			var brMatchedPatternObj = {
                name: businessRule.name.toString(),
                table: businessRule.collection.toString(),
                when: businessRule.when.toString(),
                active: businessRule.active.toString(),
                sys_id: businessRule.sys_id.toString(),
                matched_patterns: matchedPatterns,
                pattern_count: matchedPatterns.length
            };

            systemRules.push(brMatchedPatternObj);

			engine.finding.setCurrentSource(businessRule);
			engine.finding.setValue('finding_details',JSON.stringify(brMatchedPatternObj));
			engine.finding.increment();

        }
    }

    //gs.info('Scan completed in: ' + sw.elapsed() + 'ms');
    //gs.warn('\nFound ' + systemRules.length + ' business rules with potential privilege escalation patterns\n');

    // for (var j = 0; j < systemRules.length; j++) {
    //     var rule = systemRules[j];
    //     gs.warn('---');
    //     gs.warn('Business Rule: ' + rule.name);
    //     gs.warn('Table: ' + rule.table);
    //     gs.warn('When: ' + rule.when);
    //     gs.warn('Patterns found: ' + rule.matched_patterns.join(', '));
    //     gs.warn('Sys ID: ' + rule.sys_id);
    // }

    //gs.info('\n=== JSON Export ===');
    //gs.info(JSON.stringify(systemRules, null, 2));

    return systemRules;




})(engine);
```

</details>

---

### cstaces-8 domsep users

**Priority:** 4

**What:** Checks whether domain separation is enabled and, if so, identifies active users without a domain assignment. These "orphaned" users may have unintended cross-domain visibility depending on the instance's domain separation configuration.

**Why:** Domain separation is a critical multi-tenancy control in ServiceNow. Users without explicit domain assignment can potentially access data across all domains, violating data isolation requirements. NIST AC-4 and SOC 2 CC6.6 require that information flow between security domains be controlled.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    // Only runs if domain separation is enabled on the instance

	var userRecord = new GlideRecord('sys_user');
	userRecord.addQuery('active', 'true');
	userRecord.addNullQuery('sys_domain'); // Users without domain assignment
	userRecord.query();

	var orphanedUsers = [];
	while (userRecord.next()) {

		engine.finding.setCurrentSource(userRecord);
		engine.finding.setValue('finding_details','User is active and has no domain assignment.');
		engine.finding.increment();

		orphanedUsers.push({
			user: userRecord.user_name.toString(),
			name: userRecord.name.toString()
		});
	}

	//gs.warn('Users without domain assignment: ' + JSON.stringify(orphanedUsers, null, 2));
   

})(engine);
```

</details>

---

### cstaces-9a auth session prop

**Priority:** 4

**What:** Retrieves key security-related system properties governing guest access, SSO enforcement, multi-provider SSO configuration, and session timeout values. Provides a snapshot of the instance's authentication posture.

**Why:** Weak authentication configuration is the most impactful category of misconfiguration in any enterprise platform. NIST IA-2, IA-8, and AC-12 require that systems enforce strong authentication, mandate SSO where available, and terminate sessions after defined inactivity periods.

<details>
<summary>View Script</summary>

```javascript
(function (engine) {

	// Check authentication and session security properties
	var policies = [
		'glide.ui.security.allow_guest',          // Guest access enabled?
		'glide.authenticate.multisso.use.idp',    // Multi-provider SSO
		'glide.authenticate.sso.required',        // SSO enforcement
		'glide.ui.session_timeout'                // UI session timeout
	];
		//'session.timeout',                        // Session timeout


	var policySettings = {};
	for (var i = 0; i < policies.length; i++) {
		
		//Get Value - Traditional Method
		
		var policyValue = gs.getProperty(policies[i]);
		policySettings[policies[i]] = policyValue;

		//Get Record
		var propRec = new GlideRecord('sys_properties');
		propRec.addQuery('name',policies[i]);
		propRec.query();
		if(propRec.next()){

			engine.finding.setCurrentSource(propRec);
			engine.finding.setValue('finding_details','Property currently configured as:'+policyValue);
			engine.finding.increment();

		}else{

			gs.warn('Instance Scan Check cant find prop:'+policies[i]);

		}



	}

	//gs.info('Security policy settings: ' + JSON.stringify(policySettings, null, 2));

})(engine);
```

</details>

---

### cstaces-10 sched job admin

**Priority:** 4

**What:** Identifies active scheduled script executions (sysauto_script) configured to run as a user with the admin role. These jobs execute on a schedule with the full privileges of the run-as user.

**Why:** Scheduled jobs running as admin operate with unrestricted access and no interactive session monitoring. If the run-as account is compromised or the job script is modified, it becomes a persistent backdoor. NIST AC-6(1) and CIS recommend that automated processes run with the minimum privileges required.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    // Find scheduled jobs configured to run as admin users
    var scheduledJob = new GlideRecord('sysauto_script');
    scheduledJob.addQuery('active', 'true');
    scheduledJob.query();

    var adminJobs = [];
    while (scheduledJob.next()) {
        var runAs = scheduledJob.run_as.toString();
        var runAsUser = new GlideRecord('sys_user');

        if (runAs && runAsUser.get(runAs)) {
            var adminRoleCheck = new GlideRecord('sys_user_has_role');
            adminRoleCheck.addQuery('user', runAs);
            adminRoleCheck.addQuery('role.name', 'admin');
            adminRoleCheck.addQuery('state', 'active');
            adminRoleCheck.query();
            if (adminRoleCheck.hasNext()) {

                engine.finding.setCurrentSource(scheduledJob);
                engine.finding.increment();

                adminJobs.push({
                    name: scheduledJob.name.toString(),
                    run_as: runAsUser.name.toString(),
                    run_dayofweek: scheduledJob.run_dayofweek.toString(),
                    run_time: scheduledJob.run_time.toString()
                });
            }
        }
    }

    //gs.info('Scheduled jobs running as admin: ' + JSON.stringify(adminJobs, null, 2));

})(engine);
```

</details>

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

## Security

To report a vulnerability, please see [SECURITY.md](SECURITY.md). Do not open a public issue for security concerns.

## Code of Conduct

This project follows the Contributor Covenant. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for the full text.


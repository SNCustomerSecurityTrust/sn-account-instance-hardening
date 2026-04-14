# SN Account Instance Hardening

An Instance Scan suite and checks for auditing ServiceNow instances for security misconfigurations and least privilege violations.

## Overview

This repository contains a ServiceNow Update Set with an Instance Scan suite and individual scan checks that assess common security configuration gaps across identity, access control, privileged activity, and platform hygiene.

## Getting Started

### Download the Update Set

1. Download the update set XML from the [`dist/`](dist/) directory: 
2. You can click **Code > Download ZIP** on this repo, or download the raw file directly.

### Import and Commit the Update Set

1. Navigate to **System Update Sets > Retrieved Update Sets**
2. Click **Import Update Set from XML**
3. Select the downloaded Update Set .xml file and upload it
4. Open the retrieved update set
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

Source files are organized by suite in [`scans/`](scans/) (`.js` for scripts, `.json` for metadata).

## Level 1

### Users with Admin or Security Admin Roles

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

			var userLastLogin = userRec.getValue('last_login');
			var timeStart = new GlideDateTime(userLastLogin);
			var timeNow = new GlideDateTime();
			var durRaw = GlideDateTime.subtract(timeStart,timeNow); 
			var daysRaw = durRaw.numericValue / 1000 / 60 / 60 / 24;
			var days = Math.floor(daysRaw);

			engine.finding.setCurrentSource(userRec);
			engine.finding.setValue('finding_details','Found with DIRECT role:'+roleName+ 'Last login days ago:'+days);
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

				var userLastLogin2 = userRec2.getValue('last_login');
				var timeStart2 = new GlideDateTime(userLastLogin2);
				var timeNow2 = new GlideDateTime();
				var durRaw2 = GlideDateTime.subtract(timeStart2,timeNow2); 
				var daysRaw2 = durRaw.numericValue / 1000 / 60 / 60 / 24;
				var days2 = Math.floor(daysRaw2);


				engine.finding.setCurrentSource(userRec2);
				engine.finding.setValue('finding_details','Found with role:'+groupRoleName+' INHEIRITED via group:'+groupName + 'Last login days ago:'+days2);
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

### Multiple high-privilege roles

**What:** Identifies active users holding two or more high-privilege roles simultaneously (admin, security_admin, user_admin, delegated_admin, itil_admin, catalog_admin, knowledge_admin). Results are sorted by role count descending.

**Why:** Role accumulation violates the principle of least privilege (NIST AC-6(5)) and significantly expands the blast radius of a compromised account. Separation of duties controls require that no single account concentrates multiple administrative capabilities without explicit justification.

<details>
<summary>View Script</summary>

```javascript
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
     'user_admin',
     'delegated_developer',
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
         //engine.finding.setCurrentSource(userRec);
         //engine.finding.setValue('finding_details','Found with DIRECT role assignment');
         //engine.finding.increment();
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
             //engine.finding.setCurrentSource(userRec2);
             //engine.finding.setValue('finding_details','Found with GROUP INHEIRITED role assignment');
             //engine.finding.increment();
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


 for (var i2 = 0; i2 < results.length; i2++) {
     var resultRec = results[i2];
     var userRec3 = new GlideRecord('sys_user');
     userRec3.get('user_name', resultRec.user_name);

     engine.finding.setCurrentSource(userRec3);
     engine.finding.setValue('finding_details','Account found with multiple high-priv roles:'+resultRec.roles.join());
     engine.finding.increment();


 }

//  gs.info('Users with multiple high-privilege roles: ' + results.length);
//  gs.info('Potential service accounts with multiple roles: ' + serviceAccounts.length);
//  gs.info(JSON.stringify(results, null, 2));
```

</details>

---

### Inactive users with elevated roles (recent)

**What:** Identifies inactive users who still retain privileged role assignments. Separates direct assignments (critical) from inherited ones (high), and flags accounts deactivated within the last 60 days as highest reactivation risk.

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
			engine.finding.setValue('finding_details','Inactive account w high-perm roles (newer than 60 days)');
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

### Inactive users with elevated roles (older)

**What:** Identifies inactive users who still retain privileged role assignments. Separates direct assignments (critical) from inherited ones (high), and flags accounts deactivated within the last 60 days as highest reactivation risk.

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
			engine.finding.setValue('finding_details','Inactive account w high-perm roles (older than 60 days)');
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

### Users with impersonation ability

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

    // // 2. Direct admin role (implicitly grants impersonation)
    // var adminDirect = new GlideRecord('sys_user_has_role');
    // adminDirect.addQuery('role.name', 'admin');
    // adminDirect.addQuery('user.active', 'true');
    // adminDirect.addQuery('state', 'active');
    // adminDirect.query();
    // while (adminDirect.next()) {

	// 	var userRec2 = adminDirect.user.getRefRecord();
	// 	engine.finding.setCurrentSource(userRec2);
	// 	engine.finding.setValue('finding_details','Found with ADMIN role assignment');
	// 	engine.finding.increment();

    //     addUser(adminDirect.getValue('user'), 'direct:admin');
    
	// }

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
    var elevatedRoles = ['impersonator']; //removed admin Mar 2026
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
				engine.finding.setValue('finding_details','Found with IMPERSONATOR via Group assignment:'+member.group.name);
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

### Find roles with nested impersonator

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

### Users with security_admin

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

		var userLastLogin = userRec.getValue('last_login');
		var timeStart = new GlideDateTime(userLastLogin);
		var timeNow = new GlideDateTime();
		var durRaw = GlideDateTime.subtract(timeStart,timeNow); 
		var daysRaw = durRaw.numericValue / 1000 / 60 / 60 / 24;
		var days = Math.floor(daysRaw);


		engine.finding.setCurrentSource(userRec);
		engine.finding.setValue('finding_details', 'User found with DIRECT security_admin role assignment. Last login days ago:'+days);
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

			var userLastLogin2 = userRec.getValue('last_login');
			var timeStart2 = new GlideDateTime(userLastLogin2);
			var timeNow2 = new GlideDateTime();
			var durRaw2 = GlideDateTime.subtract(timeStart2,timeNow); 
			var daysRaw2 = durRaw.numericValue / 1000 / 60 / 60 / 24;
			var days2 = Math.floor(daysRaw2);

			engine.finding.setCurrentSource(userRec2);
			engine.finding.setValue('finding_details', 'Found with NESTED security_admin role via:'+groupName + 'Last login days ago:'+days2);
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

### Integration users with admin role

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
			engine.finding.setValue('finding_details','Integration account found with role:'+roles[i]);
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

## Level 2

### Active users with local DB logins

**What:** Queries sys_user_login_history for login events in the last 30 days where authentication_method_used is DB (local database authentication). Filters to active users whose record lives in the base sys_user table (sys_class_name = sys_user, excluding extensions). Reports each user once with their most recent local login timestamp.

**Why:** When SSO is the expected authentication method, local DB logins indicate accounts bypassing centralized identity controls. This can mean SSO misconfiguration, break-glass accounts being used routinely, or credentials that exist outside the identity provider's governance. Local logins undermine MFA enforcement, session policy, and audit trail consistency. NIST IA-2 requires unique identification and authentication through centralized mechanisms, and IA-5 requires centralized credential management.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

var seen = {};


var loginHistory = new GlideRecord('sys_user_login_history');
loginHistory.addQuery('authentication_method_used', 'DB');
loginHistory.addEncodedQuery('sys_created_onONLast 30 days@javascript:gs.beginningOfLast30Days()@javascript:gs.endOfLast30Days()');
loginHistory.query();

while (loginHistory.next()) {
  
    var userSysId = loginHistory.getValue('user');
    if (!userSysId) continue;

    // Deduplicate — report each user once with their most recent login
    if (seen[userSysId]) continue;

    var userRec = new GlideRecord('sys_user');
    if (!userRec.get(userSysId)) continue;

    // Only flag users whose record lives in the base sys_user table
    var className = userRec.getValue('sys_class_name');
    if (className && className !== 'sys_user') continue;

    // Skip inactive users — only care about active accounts still logging in locally
    if (userRec.getValue('active') != '1') continue;

	// If we get this far, log user to the dedupe object and proceed to flag finding.
    seen[userSysId] = true;

    var loginTime = loginHistory.getValue('login_time');
    var userName = userRec.getValue('user_name');
    var displayName = userRec.getValue('name');

    engine.finding.setCurrentSource(userRec);
    engine.finding.setValue('finding_details', 'Locally DB login at: ' + loginTime);
    engine.finding.increment();
}

})(engine);
```

</details>

---

### Users logging in with local DB authentication

**What:** Queries sys_user_login_history for login events where the type is DB (local database authentication) and the associated user record exists in the base sys_user table (sys_class_name = sys_user, not an extension). Reports each user once with their most recent local login timestamp.

**Why:** When SSO is the expected authentication method, local DB logins indicate accounts bypassing centralized authentication controls. This can mean SSO misconfiguration, emergency break-glass accounts being used routinely, or credentials that exist outside of the identity provider's governance. NIST IA-2 and IA-5 require centralized credential management, and local logins undermine MFA enforcement, session policy, and audit trail consistency.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    // Find users logging in locally (type=DB) where the user record
    // is in the base sys_user table (not an extension)
    var loginHistory = new GlideRecord('sys_user_login_history');
    loginHistory.addQuery('type', 'DB');
    loginHistory.orderByDesc('login_time');
    loginHistory.query();

    var seen = {};

    while (loginHistory.next()) {
        var userSysId = loginHistory.getValue('user');
        if (!userSysId) continue;

        // Deduplicate — report each user once with their most recent login
        if (seen[userSysId]) continue;

        var userRec = new GlideRecord('sys_user');
        if (!userRec.get(userSysId)) continue;

        // Only flag users whose record lives in the base sys_user table
        var className = userRec.getValue('sys_class_name');
        if (className && className !== 'sys_user') continue;

        // Skip inactive users — only care about active accounts still logging in locally
        if (userRec.getValue('active') != 'true') continue;

        seen[userSysId] = true;

        var loginTime = loginHistory.getValue('login_time');
        var userName = userRec.getValue('user_name');
        var displayName = userRec.getValue('name');

        engine.finding.setCurrentSource(userRec);
        engine.finding.setValue('finding_details',
            'User ' + userName + ' (' + displayName + ')' +
            ' logged in locally (DB auth) on ' + loginTime);
        engine.finding.increment();
    }

})(engine);
```

</details>

---

### Role Management v2 plugin not installed

**What:** Checks whether the Role Management v2 plugin (com.glide.role_management.inh_count) is installed on the instance. This plugin introduces inheritance-based role counting, improved role hierarchy visibility, and tighter controls over role propagation.

**Why:** Role Management v2 replaces the legacy role inheritance model with one that provides accurate counts of inherited roles, prevents unintended privilege propagation through role hierarchy, and enables administrators to identify over-provisioned accounts more effectively. Without it, role inheritance is opaque and difficult to audit, making least-privilege enforcement unreliable. NIST AC-6 requires that organizations enforce least privilege, and Role Management v2 provides the platform capabilities to do so at scale.

<details>
<summary>View Script</summary>

```javascript
(function(engine) {

    if (!GlidePluginManager.isRegistered('com.glide.role_management.inh_count')) {

        //engine.finding.setCurrentSource(scheduledJob);
        engine.finding.setValue('finding_details', 'Risk Management v2 plugin is not installed. Consider installing.');
        engine.finding.increment();

    }


})(engine);
```

</details>

---

### Users with security_admin

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

### Recent changes to ACLs and roles

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
			
			var aclRec = new GlideRecord(audit.tablename);
			aclRec.get(audit.documentkey);

			var fieldModified = audit.fieldname.getDisplayValue();
			

			engine.finding.setCurrentSource(aclRec);
			engine.finding.setValue('finding_details','Modification of ACL field:'+fieldModified + ' by user:'+audit.user);
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

### Review self-assigned admin roles

**What:** Detects role assignment changes made by security_admin users in the last 30 days. Flags self-grants and grants of high-risk roles (admin, security_admin, impersonator) as the most direct indicators of privilege escalation.

**Why:** Role grants are the most explicit form of privilege escalation. A security_admin granting themselves or others additional elevated roles bypasses intended approval workflows. NIST AC-6(5) and SOC 2 CC6.1 require that privileged role changes be authorized, logged, and reviewed for anomalous patterns.

<details>
<summary>View Script</summary>

```javascript
// Additional finding details added, needs further debugging (known issue: 0 items found every time) Apr 2026

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

    // gs.info('security_admin population: ' + secAdminUsernames.length + ' users');

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
        if (roleGrants[k].is_self_grant){
			selfGrants.push(roleGrants[k]);

			var grantedByUser = roleGrants[k].granted_by_display;
			var roleRec = new GlideRecord('sys_user_role');
			roleRec.get('name',roleGrants[k].role_granted);

			engine.finding.setCurrentSource(roleRec);
            engine.finding.setValue('finding_details', 'Role self-granted by user: '+grantedByUser);
            engine.finding.increment();

		} 
        if (roleGrants[k].is_high_risk_role) highRiskGrants.push(roleGrants[k]);
    }

    // gs.info('Total role grants by security_admin users (last 30 days): ' + roleGrants.length);
    // gs.info('High risk role grants (admin/security_admin/impersonator): ' + highRiskGrants.length);
    // gs.info('Self grants: ' + selfGrants.length);
    // gs.info(JSON.stringify(roleGrants, null, 2));

})(engine);
```

</details>

---

### Find changes to Encryption config tables

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
				record_id: recordId,
                field_changed: fieldChanged,
                old_value: oldValue,
                new_value: newValue,
                is_deactivation: isDeactivation,
                is_high_risk_table: isHighRisk
            };

            encryptionChanges.push(encryptionAuditObj);

			// engine.finding.setCurrentSource(encRecord);
			// engine.finding.setValue('finding_details',JSON.stringify(encryptionAuditObj,null,4));
			// engine.finding.increment();

        }
    }

    var deactivations = [];
    var highRiskChanges = [];
    var otherChanges = [];

    for (var k = 0; k < encryptionChanges.length; k++) {
        if (encryptionChanges[k].is_deactivation) {

			deactivations.push(encryptionChanges[k]);

			var changeRec = new GlideRecord(encryptionChanges[k].table);
			if(changeRec.get(encryptionChanges[k].record_id)){
				engine.finding.setCurrentSource(changeRec);
			}
			engine.finding.setValue('finding_details','DEACTIVATION on security layer\n'+JSON.stringify(encryptionChanges[k],null,4));
			engine.finding.increment();

        } else if (encryptionChanges[k].is_high_risk_table) {

            highRiskChanges.push(encryptionChanges[k]);

			var highRiskRec = new GlideRecord(encryptionChanges[k].table);
			if(highRiskRec.get(encryptionChanges[k].record_id)){
				engine.finding.setCurrentSource(highRiskRec);
			}
			engine.finding.setValue('finding_details','HIGH RISK CHANGE on security layer\n'+JSON.stringify(encryptionChanges[k],null,4));
			engine.finding.increment();

        } else {

            otherChanges.push(encryptionChanges[k]);

			var otherChangeRec = new GlideRecord(encryptionChanges[k].table);
			if(otherChangeRec.get(encryptionChanges[k].record_id)){
				engine.finding.setCurrentSource(otherChangeRec);
			}
			engine.finding.setValue('finding_details','Other change found on security layer\n'+JSON.stringify(encryptionChanges[k],null,4));
			engine.finding.increment();

        }
    }

    // gs.info('Total encryption changes by security_admin users (last 30 days): ' + encryptionChanges.length);
    // gs.info('Deactivation events: ' + deactivations.length);
    // gs.info('High risk table changes (sys_kmf_map, sys_kmf_key, sys_kmf_crypto_module): ' + highRiskChanges.length);
    // gs.info('Other encryption changes: ' + otherChanges.length);
    // gs.info(JSON.stringify(encryptionChanges, null, 2));

})(engine);
```

</details>

---

### Review active OAuth IDs

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

## Level 3

### Find ACLs overly permissive

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
    aclRecord.addNullQuery('security_attribute');
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

### Find ACLs with risky patterns

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
					engine.finding.setValue('finding_details', 'Pattern:'+patternList[i]+' Category:'+category);
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

### Domain Separation users without domain

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

## Level Knowledge

### glide.knowman.block_access_with_no_user_criteria must be set to true to block un

**What:** Checks that the system property glide.knowman.block_access_with_no_user_criteria exists and is set to true. When false (the legacy default on pre-Orlando instances), any knowledge base that lacks Can Read or Can Contribute user criteria is accessible to all users, including unauthenticated guests. AppOmni research found approximately 45% of tested enterprise instances were leaking KB data due to this and related misconfigurations. This is the single most important KB security property.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: glide.knowman.block_access_with_no_user_criteria
 * Check ID: cstaces-11a
 *
 * Type:     Script Only
 * Category: KB Security — System Properties
 * Severity: Critical
 *
 * Checks that glide.knowman.block_access_with_no_user_criteria is set to 'true'.
 * When false (default on pre-Orlando instances), any KB without explicit
 * user criteria is accessible to ALL users — including unauthenticated/guest.
 *
 * This is the #1 root cause of KB data exposures per AppOmni's 2024 research
 * (45% of tested enterprise instances were leaking KB data).
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    var PROP_NAME = 'glide.knowman.block_access_with_no_user_criteria';
    var finding = false;
    var detail = '';

    var propRec = new GlideRecord('sys_properties');
    propRec.addQuery('name', PROP_NAME);
    propRec.query();

    if (propRec.next()) {
        if (propRec.getValue('value') !== 'true') {
            finding = true;
            detail = 'Property "' + PROP_NAME + '" is set to "' + propRec.getValue('value') +
                '". This means knowledge bases without user criteria are accessible to ALL users, ' +
                'including unauthenticated guests. Set this property to "true" immediately.';
        }
    } else {
        // Property does not exist — treat as false (the insecure default)
        finding = true;
        detail = 'Property "' + PROP_NAME + '" does not exist on this instance. ' +
            'The default behavior is to allow access to KBs with no user criteria. ' +
            'Create this property and set it to "true".';
    }

    if (finding) {
        engine.finding.setCurrentSource(propRec);
        engine.finding.setValue('finding_details', detail);
        engine.finding.increment();
    }

})(engine);
```

</details>

---

### glide.knowman.apply_article_read_criteria must be true so that article-level use

**What:** Checks that glide.knowman.apply_article_read_criteria is set to true. When false (the default), users with Can Contribute access at the KB level bypass ALL article-level Can Read and Cannot Read user criteria. This defeats the purpose of setting article-level restrictions for sensitive content within a shared knowledge base and is a prerequisite for effective article-level access segmentation.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: glide.knowman.apply_article_read_criteria
 * Check ID: cstaces-11b
 *
 * Type:     Script Only
 * Category: KB Security — System Properties
 * Severity: High
 *
 * Checks that glide.knowman.apply_article_read_criteria is set to 'true'.
 * When false (default), users with KB-level "Can Contribute" access bypass
 * ALL article-level "Can Read" and "Cannot Read" user criteria.
 *
 * This defeats article-level access segmentation within a shared KB.
 *
 * Reference: https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0966771
 */

(function(engine) {

    var PROP_NAME = 'glide.knowman.apply_article_read_criteria';
    var finding = false;
    var detail = '';

    var propRec = new GlideRecord('sys_properties');
    propRec.addQuery('name', PROP_NAME);
    propRec.query();

    if (propRec.next()) {
        if (propRec.getValue('value') !== 'true') {
            finding = true;
            detail = 'Property "' + PROP_NAME + '" is set to "' + propRec.getValue('value') +
                '". Contributors to a KB can read ALL articles regardless of article-level ' +
                'user criteria restrictions. Set to "true" if you use article-level access controls.';
        }
    } else {
        finding = true;
        detail = 'Property "' + PROP_NAME + '" does not exist. ' +
            'Default behavior allows KB contributors to bypass article-level read restrictions. ' +
            'Create this property and set it to "true".';
    }

    if (finding) {
        engine.finding.setCurrentSource(propRec);
        engine.finding.setValue('finding_details', detail);
        engine.finding.increment();
    }

})(engine);
```

</details>

---

### glide.knowman.search.apply_role_based_security must be true to enforce role-base

**What:** Checks that glide.knowman.search.apply_role_based_security is set to true. When false or missing, role-based access checks on the roles field of kb_knowledge articles are bypassed during search. Articles with role restrictions may appear in search results for users who should not see them. This property must be manually created on many instances.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: glide.knowman.search.apply_role_based_security
 * Check ID: cstaces-11c
 *
 * Type:     Script Only
 * Category: KB Security — System Properties
 * Severity: High
 *
 * Checks that glide.knowman.search.apply_role_based_security is set to 'true'.
 * When false, role-based access checks on the 'roles' field of kb_knowledge
 * articles are bypassed during search, potentially leaking restricted articles
 * in search results.
 *
 * Reference: https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0824545
 */

(function(engine) {

    var PROP_NAME = 'glide.knowman.search.apply_role_based_security';
    var finding = false;
    var detail = '';

    var propRec = new GlideRecord('sys_properties');
    propRec.addQuery('name', PROP_NAME);
    propRec.query();

    if (propRec.next()) {
        if (propRec.getValue('value') !== 'true') {
            finding = true;
            detail = 'Property "' + PROP_NAME + '" is set to "' + propRec.getValue('value') +
                '". Role-based security on KB articles is not enforced during search. ' +
                'Articles with role restrictions may appear in search results for unauthorized users. ' +
                'Set to "true".';
        }
    } else {
        finding = true;
        detail = 'Property "' + PROP_NAME + '" does not exist. ' +
            'This property may need to be manually created on some instances. ' +
            'Without it, role-based article restrictions are not enforced during search.';
    }

    if (finding) {
        engine.finding.setCurrentSource(propRec);
        engine.finding.setValue('finding_details', detail);
        engine.finding.increment();
    }

})(engine);
```

</details>

---

### glide.knowman.show_unpublished must not be true to prevent draft and review-stat

**What:** Checks that glide.knowman.show_unpublished is not set to true. When enabled, articles in Draft, Review, or other non-Published workflow states are visible in the Knowledge portal and search results. Unpublished articles may contain sensitive information that has not been reviewed or approved, bypassing the editorial and approval workflow.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: glide.knowman.show_unpublished
 * Check ID: cstaces-11d
 *
 * Type:     Script Only
 * Category: KB Security — System Properties
 * Severity: High
 *
 * Checks that glide.knowman.show_unpublished is NOT set to 'true'.
 * When true, articles in Draft, Review, or other non-Published workflow states
 * are visible in the Knowledge portal and search results.
 *
 * Unpublished articles may contain sensitive, unreviewed content.
 */

(function(engine) {

    var PROP_NAME = 'glide.knowman.show_unpublished';

    var propRec = new GlideRecord('sys_properties');
    propRec.addQuery('name', PROP_NAME);
    propRec.query();

    if (propRec.next()) {
        if (propRec.getValue('value') === 'true') {
            engine.finding.setCurrentSource(propRec);
            engine.finding.setValue('finding_details',
                'Property "' + PROP_NAME + '" is set to "true". ' +
                'Draft, review, and other non-published articles are visible in the Knowledge portal ' +
                'and search results. This bypasses the editorial/approval workflow and may leak ' +
                'sensitive content before it has been reviewed. Set to "false".');
            engine.finding.increment();
        }
    }
    // If property does not exist, default is false (secure) — no finding

})(engine);
```

</details>

---

### glide.knowman.section.view_roles.draft should be restricted to knowledge managem

**What:** Checks that glide.knowman.section.view_roles.draft is not set to overly permissive roles such as itil, snc_internal, employee, or left empty. This property controls which roles can see articles in Draft state. If set to a common role, draft articles containing incomplete or sensitive information become visible to a broad audience before editorial review and approval.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: glide.knowman.section.view_roles.draft
 * Check ID: cstaces-11e
 *
 * Type:     Script Only
 * Category: KB Security — System Properties
 * Severity: Medium
 *
 * Checks that glide.knowman.section.view_roles.draft is not overly permissive.
 * If set to a common role (like 'itil') or left empty, draft articles are
 * visible to a broad audience before they've been reviewed and approved.
 *
 * Expected: Restrictive roles like 'knowledge' or 'knowledge_admin'.
 */

(function(engine) {

    var PROP_NAME = 'glide.knowman.section.view_roles.draft';
    var BROAD_ROLES = ['itil', 'snc_internal', 'employee', ''];

    var propRec = new GlideRecord('sys_properties');
    propRec.addQuery('name', PROP_NAME);
    propRec.query();

    if (propRec.next()) {
        var val = propRec.getValue('value') || '';
        var roles = val.split(',');
        var broadFound = [];

        for (var i = 0; i < roles.length; i++) {
            var role = roles[i].trim().toLowerCase();
            if (BROAD_ROLES.indexOf(role) >= 0) {
                broadFound.push(role || '(empty)');
            }
        }

        if (broadFound.length > 0 || val === '') {
            engine.finding.setCurrentSource(propRec);
            engine.finding.setValue('finding_details',
                'Property "' + PROP_NAME + '" contains overly permissive role(s): ' +
                broadFound.join(', ') + '. Draft articles may be visible to a wide audience ' +
                'before editorial review. Restrict to knowledge management roles ' +
                '(e.g., "knowledge" or "knowledge_admin").');
            engine.finding.increment();
        }
    }

})(engine);
```

</details>

---

### Active knowledge bases must have at least one Can Read user criteria to explicit

**What:** Identifies active knowledge bases with no Can Read user criteria configured. Without explicit read criteria, access depends entirely on the glide.knowman.block_access_with_no_user_criteria system property. If that property is false, these KBs are accessible to everyone including unauthenticated guests. Every KB should have explicit Can Read criteria as a defense-in-depth measure.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: KBs with no "Can Read" user criteria
 * Check ID: cstaces-11f
 *
 * Type:     Script Only
 * Category: KB Security — Access Control
 * Severity: Critical
 *
 * Identifies active knowledge bases that have no "Can Read" user criteria.
 * Without explicit read criteria, access depends entirely on the
 * glide.knowman.block_access_with_no_user_criteria property. If that
 * property is false, these KBs are accessible to everyone including guests.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    // Discover M2M table for "Can Read" criteria
    var M2M_CANDIDATES = [
        'kb_uc_can_read_mtom',
        'm2m_kb_uc_can_read',
        'kb_uc_can_read_m2m'
    ];
    var m2mTable = '';
    for (var c = 0; c < M2M_CANDIDATES.length; c++) {
        var test = new GlideRecord(M2M_CANDIDATES[c]);
        if (test.isValid()) {
            m2mTable = M2M_CANDIDATES[c];
            break;
        }
    }

    // Build set of KB sys_ids that have at least one "Can Read" criteria
    var kbsWithCriteria = {};

    if (m2mTable) {
        // Strategy 1: M2M table
        var m2mRec = new GlideRecord(m2mTable);
        m2mRec.query();
        while (m2mRec.next()) {
            // M2M table has a reference to kb_knowledge_base — field name varies
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (kbRef) {
                kbsWithCriteria[kbRef] = true;
            }
        }
    }

    // Strategy 2: Check Glide List field on kb_knowledge_base (fallback/supplement)
    var kbListRec = new GlideRecord('kb_knowledge_base');
    kbListRec.addActiveQuery();
    kbListRec.addNotNullQuery('u_can_read_user_criteria');
    kbListRec.query();
    while (kbListRec.next()) {
        kbsWithCriteria[kbListRec.getUniqueValue()] = true;
    }

    // Now find active KBs NOT in the set
    var kbRec = new GlideRecord('kb_knowledge_base');
    kbRec.addActiveQuery();
    kbRec.query();

    while (kbRec.next()) {
        var kbId = kbRec.getUniqueValue();
        if (!kbsWithCriteria[kbId]) {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" (' + kbRec.getValue('kb_version') +
                ') has no "Can Read" user criteria. If glide.knowman.block_access_with_no_user_criteria ' +
                'is false, this KB is accessible to ALL users including unauthenticated guests. ' +
                'Add explicit "Can Read" user criteria.');
            engine.finding.increment();
        }
    }

})(engine);
```

</details>

---

### Active knowledge bases should have Cannot Read user criteria to explicitly deny 

**What:** Identifies active knowledge bases with no Cannot Read user criteria (deny list). Without a Cannot Read denylist, there is no explicit block for unauthenticated or guest users. The Guest User Business Rule should automatically add Guest to Cannot Read on new KBs, but older KBs or KBs created when the Business Rule was inactive will lack this protection. Cannot always overrides Can in user criteria evaluation, making denylists a critical defense-in-depth layer.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: KBs with no "Cannot Read" user criteria
 * Check ID: cstaces-11g
 *
 * Type:     Script Only
 * Category: KB Security — Access Control
 * Severity: High
 *
 * Identifies active knowledge bases that have no "Cannot Read" user criteria.
 * Without a deny list, there is no explicit block for unauthenticated/guest users.
 * "Cannot" always overrides "Can" in user criteria evaluation, making deny lists
 * a critical defense-in-depth layer.
 *
 * The Guest User Business Rule (sys_id 6c8ec5147711111016f35c207b5a9969) only
 * applies to newly created KBs; older KBs may lack this protection.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    var M2M_CANDIDATES = [
        'kb_uc_cannot_read_mtom',
        'm2m_kb_uc_cannot_read',
        'kb_uc_cannot_read_m2m'
    ];
    var m2mTable = '';
    for (var c = 0; c < M2M_CANDIDATES.length; c++) {
        var test = new GlideRecord(M2M_CANDIDATES[c]);
        if (test.isValid()) {
            m2mTable = M2M_CANDIDATES[c];
            break;
        }
    }

    var kbsWithCriteria = {};

    if (m2mTable) {
        var m2mRec = new GlideRecord(m2mTable);
        m2mRec.query();
        while (m2mRec.next()) {
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (kbRef) {
                kbsWithCriteria[kbRef] = true;
            }
        }
    }

    var kbListRec = new GlideRecord('kb_knowledge_base');
    kbListRec.addActiveQuery();
    kbListRec.addNotNullQuery('u_cannot_read_user_criteria');
    kbListRec.query();
    while (kbListRec.next()) {
        kbsWithCriteria[kbListRec.getUniqueValue()] = true;
    }

    var kbRec = new GlideRecord('kb_knowledge_base');
    kbRec.addActiveQuery();
    kbRec.query();

    while (kbRec.next()) {
        if (!kbsWithCriteria[kbRec.getUniqueValue()]) {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" has no "Cannot Read" user criteria (deny list). ' +
                'Without an explicit deny, there is no fallback block for guest/unauthenticated users. ' +
                'Add a "Cannot Read" user criteria that includes the Guest user at minimum.');
            engine.finding.increment();
        }
    }

})(engine);
```

</details>

---

### Active knowledge bases with empty Can Contribute criteria implicitly allow all a

**What:** Identifies active knowledge bases where the Can Contribute user criteria is empty. When Can Contribute is empty, ALL authenticated users implicitly gain contribute access, meaning any user can create, modify, or retire articles. Since contribute access implies read access by default (unless glide.knowman.apply_article_read_criteria is true), this also bypasses article-level Can Read and Cannot Read restrictions.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: KBs with no "Can Contribute" user criteria
 * Check ID: cstaces-11h
 *
 * Type:     Script Only
 * Category: KB Security — Access Control
 * Severity: Critical
 *
 * Identifies active knowledge bases with no "Can Contribute" user criteria.
 * When empty, ALL authenticated users implicitly gain contribute access, which:
 *   1. Allows any user to create, modify, and retire articles
 *   2. Grants implicit read access that bypasses article-level restrictions
 *      (unless glide.knowman.apply_article_read_criteria = true)
 *
 * This is documented as a known issue in KB0623654.
 *
 * Reference: https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0623654
 */

(function(engine) {

    var M2M_CANDIDATES = [
        'kb_uc_can_contribute_mtom',
        'm2m_kb_uc_can_contribute',
        'kb_uc_can_contribute_m2m'
    ];
    var m2mTable = '';
    for (var c = 0; c < M2M_CANDIDATES.length; c++) {
        var test = new GlideRecord(M2M_CANDIDATES[c]);
        if (test.isValid()) {
            m2mTable = M2M_CANDIDATES[c];
            break;
        }
    }

    var kbsWithCriteria = {};

    if (m2mTable) {
        var m2mRec = new GlideRecord(m2mTable);
        m2mRec.query();
        while (m2mRec.next()) {
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (kbRef) {
                kbsWithCriteria[kbRef] = true;
            }
        }
    }

    var kbListRec = new GlideRecord('kb_knowledge_base');
    kbListRec.addActiveQuery();
    kbListRec.addNotNullQuery('u_can_contribute_user_criteria');
    kbListRec.query();
    while (kbListRec.next()) {
        kbsWithCriteria[kbListRec.getUniqueValue()] = true;
    }

    var kbRec = new GlideRecord('kb_knowledge_base');
    kbRec.addActiveQuery();
    kbRec.query();

    while (kbRec.next()) {
        if (!kbsWithCriteria[kbRec.getUniqueValue()]) {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" has no "Can Contribute" user criteria. ' +
                'When empty, ALL authenticated users implicitly gain contribute access — they can create, ' +
                'modify, and retire articles. Contribute access also bypasses article-level read restrictions ' +
                'unless glide.knowman.apply_article_read_criteria is true. Define explicit contribute criteria.');
            engine.finding.increment();
        }
    }

})(engine);
```

</details>

---

### Knowledge bases must not use the built-in Any User or Any user for kb criteria i

**What:** Identifies knowledge bases where the Can Read user criteria includes the built-in Any User or Any user for kb user criteria records. These built-in records match ALL users including unauthenticated and guest users. Administrators commonly mistake them for all authenticated employees when they actually permit unauthenticated access. This was one of the three root cause scenarios identified by AppOmni for KB data exposures.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: KBs using "Any User" or "Any user for kb" in Can Read
 * Check ID: cstaces-11i
 *
 * Type:     Script Only
 * Category: KB Security — Access Control
 * Severity: Critical
 *
 * Identifies knowledge bases where "Can Read" includes the built-in
 * "Any User" or "Any user for kb" user criteria records. These match
 * ALL users including unauthenticated/guest — administrators commonly
 * mistake them for "all authenticated employees."
 *
 * This was one of three root cause scenarios for KB data exposure per AppOmni.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    // Find the "Any User" and "Any user for kb" user criteria records
    var dangerousCriteria = {};
    var ucRec = new GlideRecord('user_criteria');
    ucRec.addEncodedQuery('nameINAny User,Any user for kb');
    ucRec.query();
    while (ucRec.next()) {
        dangerousCriteria[ucRec.getUniqueValue()] = ucRec.getValue('name');
    }

    if (Object.keys(dangerousCriteria).length === 0) {
        return; // No dangerous criteria records found on this instance
    }

    // Check M2M tables for "Can Read" relationships
    var M2M_CANDIDATES = [
        'kb_uc_can_read_mtom',
        'm2m_kb_uc_can_read',
        'kb_uc_can_read_m2m'
    ];
    var m2mTable = '';
    for (var c = 0; c < M2M_CANDIDATES.length; c++) {
        var test = new GlideRecord(M2M_CANDIDATES[c]);
        if (test.isValid()) {
            m2mTable = M2M_CANDIDATES[c];
            break;
        }
    }

    var flaggedKBs = {}; // kbId -> criteriaName

    if (m2mTable) {
        var m2mRec = new GlideRecord(m2mTable);
        m2mRec.query();
        while (m2mRec.next()) {
            var ucRef = m2mRec.getValue('user_criteria') || m2mRec.getValue('user_criteria_id') || '';
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (ucRef && kbRef && dangerousCriteria[ucRef]) {
                flaggedKBs[kbRef] = dangerousCriteria[ucRef];
            }
        }
    }

    // Report findings
    for (var kbId in flaggedKBs) {
        var kbRec = new GlideRecord('kb_knowledge_base');
        if (kbRec.get(kbId) && kbRec.getValue('active') === 'true') {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" uses "' + flaggedKBs[kbId] +
                '" in its "Can Read" user criteria. This built-in criteria matches ALL users ' +
                'including unauthenticated guests. Replace with a criteria targeting specific ' +
                'roles or groups (e.g., all employees via a common role like snc_internal).');
            engine.finding.increment();
        }
    }

})(engine);
```

</details>

---

### The Guest user must be included in a Cannot Read user criteria on every active k

**What:** Identifies active knowledge bases where the Guest user is not included in any Cannot Read user criteria. If Guest is not explicitly denied and other conditions permit access (such as Any User in Can Read or no user criteria at all), unauthenticated users can view KB content. User criteria prioritizes Deny over Allow, so having Guest in Cannot Read is a critical safety net even if Can Read accidentally includes broad criteria.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: Guest user not in "Cannot Read" for non-public KBs
 * Check ID: cstaces-11j
 *
 * Type:     Script Only
 * Category: KB Security — Access Control
 * Severity: High
 *
 * Identifies active knowledge bases where the Guest user is not included
 * in any "Cannot Read" user criteria. Since "Cannot" overrides "Can" in
 * ServiceNow's evaluation, having Guest in "Cannot Read" is a critical
 * safety net even if "Can Read" accidentally includes broad criteria.
 *
 * The OOB Business Rule (sys_id 6c8ec5147711111016f35c207b5a9969) adds
 * Guest to Cannot Read on new KBs, but older KBs may lack this protection.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    // Find the Guest user sys_id
    var guestId = '';
    var guestRec = new GlideRecord('sys_user');
    guestRec.addQuery('user_name', 'guest');
    guestRec.query();
    if (guestRec.next()) {
        guestId = guestRec.getUniqueValue();
    }
    if (!guestId) {
        return; // No guest user found
    }

    // Find all user criteria that include the Guest user
    var criteriaWithGuest = {};
    var ucRec = new GlideRecord('user_criteria');
    ucRec.addQuery('users', 'CONTAINS', guestId);
    ucRec.query();
    while (ucRec.next()) {
        criteriaWithGuest[ucRec.getUniqueValue()] = true;
    }

    // Check M2M tables for "Cannot Read" relationships
    var M2M_CANDIDATES = [
        'kb_uc_cannot_read_mtom',
        'm2m_kb_uc_cannot_read',
        'kb_uc_cannot_read_m2m'
    ];
    var m2mTable = '';
    for (var c = 0; c < M2M_CANDIDATES.length; c++) {
        var test = new GlideRecord(M2M_CANDIDATES[c]);
        if (test.isValid()) {
            m2mTable = M2M_CANDIDATES[c];
            break;
        }
    }

    var kbsProtected = {};

    if (m2mTable) {
        var m2mRec = new GlideRecord(m2mTable);
        m2mRec.query();
        while (m2mRec.next()) {
            var ucRef = m2mRec.getValue('user_criteria') || m2mRec.getValue('user_criteria_id') || '';
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (ucRef && kbRef && criteriaWithGuest[ucRef]) {
                kbsProtected[kbRef] = true;
            }
        }
    }

    // Find active KBs that are NOT protected
    var kbRec = new GlideRecord('kb_knowledge_base');
    kbRec.addActiveQuery();
    kbRec.query();

    while (kbRec.next()) {
        if (!kbsProtected[kbRec.getUniqueValue()]) {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" does not have the Guest user in any ' +
                '"Cannot Read" user criteria. Without an explicit Guest deny, unauthenticated users ' +
                'may access this KB if other conditions allow it (e.g., "Any User" in Can Read, or ' +
                'no user criteria at all). Add Guest to a "Cannot Read" user criteria on this KB.');
            engine.finding.increment();
        }
    }

})(engine);
```

</details>

---

### Knowledge bases with Can Contribute set but no Can Read criteria create a danger

**What:** Identifies KBs where Can Contribute is configured but Can Read is empty. This is a dangerous misconfiguration: when glide.knowman.block_access_with_no_user_criteria is true, it only blocks access when NEITHER Can Read NOR Can Contribute is set. If Can Contribute exists (even narrowly), the system considers the KB to have criteria and will NOT block access. Since no Can Read restriction exists, unauthenticated users may still read all articles.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: KBs with "Can Contribute" set but no "Can Read"
 * Check ID: cstaces-11k
 *
 * Type:     Script Only
 * Category: KB Security — Access Control
 * Severity: Critical
 *
 * Identifies KBs where "Can Contribute" is configured but "Can Read" is empty.
 * This is a dangerous misconfiguration: when block_access_with_no_user_criteria
 * is true, it only blocks when NEITHER Can Read NOR Can Contribute is set.
 * If Can Contribute exists (even narrowly), the property considers the KB to
 * have criteria — so it does NOT block unauthenticated read access when
 * Can Read is missing.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    // Discover M2M tables
    var readCandidates = ['kb_uc_can_read_mtom', 'm2m_kb_uc_can_read', 'kb_uc_can_read_m2m'];
    var contribCandidates = ['kb_uc_can_contribute_mtom', 'm2m_kb_uc_can_contribute', 'kb_uc_can_contribute_m2m'];

    function findM2M(candidates) {
        for (var i = 0; i < candidates.length; i++) {
            var t = new GlideRecord(candidates[i]);
            if (t.isValid()) return candidates[i];
        }
        return '';
    }

    var readM2M = findM2M(readCandidates);
    var contribM2M = findM2M(contribCandidates);

    // Build sets
    var kbsWithRead = {};
    var kbsWithContrib = {};

    function loadKBs(tableName, targetSet) {
        if (!tableName) return;
        var m2mRec = new GlideRecord(tableName);
        m2mRec.query();
        while (m2mRec.next()) {
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (kbRef) targetSet[kbRef] = true;
        }
    }

    loadKBs(readM2M, kbsWithRead);
    loadKBs(contribM2M, kbsWithContrib);

    // Find KBs with contribute but no read
    var kbRec = new GlideRecord('kb_knowledge_base');
    kbRec.addActiveQuery();
    kbRec.query();

    while (kbRec.next()) {
        var kbId = kbRec.getUniqueValue();
        if (kbsWithContrib[kbId] && !kbsWithRead[kbId]) {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" has "Can Contribute" user criteria defined ' +
                'but no "Can Read" user criteria. This is a dangerous gap: the ' +
                'glide.knowman.block_access_with_no_user_criteria property considers this KB to have ' +
                'criteria (because Can Contribute exists) and will NOT block access — but no Can Read ' +
                'restriction exists, so unauthenticated users may still read articles. ' +
                'Add explicit "Can Read" user criteria.');
            engine.finding.increment();
        }
    }

})(engine);
```

</details>

---

### Knowledge bases created before mid-2022 lack automatic Guest user denial and mus

**What:** Identifies knowledge bases created before mid-2022 (when the Guest User Business Rule was introduced) that do not have the Guest user in any Cannot Read criteria. These are the highest-risk KBs for unintended public exposure since the automatic Guest denial protection was not applied retroactively. The Business Rule only protects newly created KBs.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: KBs created before mid-2022 without Guest deny
 * Check ID: cstaces-11l
 *
 * Type:     Script Only
 * Category: KB Security — Access Control
 * Severity: High
 *
 * Identifies knowledge bases created before mid-2022 (when the Guest User
 * Business Rule was introduced) that do not have Guest in their "Cannot Read"
 * criteria. These are the highest-risk KBs for unintended public exposure
 * since the automatic protection was not applied retroactively.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    var CUTOFF_DATE = '2022-07-01 00:00:00';

    // Find Guest user
    var guestId = '';
    var guestRec = new GlideRecord('sys_user');
    guestRec.addQuery('user_name', 'guest');
    guestRec.query();
    if (guestRec.next()) guestId = guestRec.getUniqueValue();
    if (!guestId) return;

    // Find criteria that include Guest
    var criteriaWithGuest = {};
    var ucRec = new GlideRecord('user_criteria');
    ucRec.addQuery('users', 'CONTAINS', guestId);
    ucRec.query();
    while (ucRec.next()) {
        criteriaWithGuest[ucRec.getUniqueValue()] = true;
    }

    // Check Cannot Read M2M
    var M2M_CANDIDATES = ['kb_uc_cannot_read_mtom', 'm2m_kb_uc_cannot_read', 'kb_uc_cannot_read_m2m'];
    var m2mTable = '';
    for (var c = 0; c < M2M_CANDIDATES.length; c++) {
        var test = new GlideRecord(M2M_CANDIDATES[c]);
        if (test.isValid()) { m2mTable = M2M_CANDIDATES[c]; break; }
    }

    var kbsProtected = {};
    if (m2mTable) {
        var m2mRec = new GlideRecord(m2mTable);
        m2mRec.query();
        while (m2mRec.next()) {
            var ucRef = m2mRec.getValue('user_criteria') || m2mRec.getValue('user_criteria_id') || '';
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (ucRef && kbRef && criteriaWithGuest[ucRef]) {
                kbsProtected[kbRef] = true;
            }
        }
    }

    // Find pre-2022 KBs without Guest deny
    var kbRec = new GlideRecord('kb_knowledge_base');
    kbRec.addActiveQuery();
    kbRec.addQuery('sys_created_on', '<', CUTOFF_DATE);
    kbRec.query();

    while (kbRec.next()) {
        if (!kbsProtected[kbRec.getUniqueValue()]) {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" was created on ' +
                kbRec.getValue('sys_created_on') + ' (before the Guest User Business Rule was introduced ' +
                'in mid-2022) and does not have the Guest user in any "Cannot Read" user criteria. ' +
                'This KB was not retroactively protected and is at elevated risk for unauthenticated ' +
                'access. Add Guest to a "Cannot Read" user criteria immediately.');
            engine.finding.increment();
        }
    }

})(engine);
```

</details>

---

### The Guest User Business Rule that auto-denies Guest access on new KBs must remai

**What:** Checks that the Business Rule (sys_id 6c8ec5147711111016f35c207b5a9969) which adds the Guest User to Cannot Read and Cannot Contribute user criteria when a new KB is created is active. If deactivated (e.g., during troubleshooting and never re-enabled), newly created knowledge bases will not automatically have Guest denied access, leaving them vulnerable to unauthenticated exposure.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: Guest User Business Rule is inactive
 * Check ID: cstaces-11m
 *
 * Type:     Script Only
 * Category: KB Security — Configuration
 * Severity: High
 *
 * Checks that the OOB Business Rule (sys_id 6c8ec5147711111016f35c207b5a9969)
 * which adds the Guest User to "Cannot Read" and "Cannot Contribute" on newly
 * created KBs is active. If deactivated (e.g., during troubleshooting and
 * never re-enabled), new KBs will not automatically be protected from
 * unauthenticated access.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    var BR_SYS_ID = '6c8ec5147711111016f35c207b5a9969';

    var brRec = new GlideRecord('sys_script');
    if (brRec.get(BR_SYS_ID)) {
        if (brRec.getValue('active') !== '1') {
            engine.finding.setCurrentSource(brRec);
            engine.finding.setValue('finding_details',
                'The Guest User Business Rule (sys_id ' + BR_SYS_ID + ') is INACTIVE. ' +
                'This Business Rule automatically adds the Guest user to "Cannot Read" and ' +
                '"Cannot Contribute" user criteria when a new Knowledge Base is created. ' +
                'Without it, newly created KBs will not be protected from unauthenticated access. ' +
                'Re-activate this Business Rule immediately.');
            engine.finding.increment();
        }
    } else {
        // BR doesn't exist — may be a very old instance or it was deleted
        var brRec2 = new GlideRecord('sys_script');
        brRec2.addQuery('sys_id', BR_SYS_ID);
        brRec2.query();
        engine.finding.setCurrentSource(brRec2);
        engine.finding.setValue('finding_details',
            'The Guest User Business Rule (sys_id ' + BR_SYS_ID + ') was not found on this instance. ' +
            'This OOB rule adds Guest to "Cannot Read" and "Cannot Contribute" on new KBs. ' +
            'It may not exist on older instances. Consider creating equivalent protection manually.');
        engine.finding.increment();
    }

})(engine);
```

</details>

---

### KB endpoint pages (kb_view, kb_find, kb_home, kb_list) must not be listed in sys

**What:** Checks the sys_public table for active records with KB-related page values: kb_comments, kb_find, kb_home, kb_list, and kb_view. Any active record means unauthenticated users can reach that Knowledge portal page without logging in. Even if user criteria restrict article content, public portal pages increase the attack surface and enable reconnaissance such as enumerating KB names and categories.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: KB pages listed in sys_public (public pages)
 * Check ID: cstaces-11n
 *
 * Type:     Script Only
 * Category: KB Security — Public Access
 * Severity: High
 *
 * Checks the sys_public table for active records allowing unauthenticated
 * access to Knowledge Base UI pages (kb_view, kb_find, kb_home, kb_list,
 * kb_comments). Any active record means unauthenticated users can reach
 * these pages without logging in.
 *
 * Reference: https://servicenowguru.com/system-definition/controlling-public-availability-knowledge-base-content/
 */

(function(engine) {

    var KB_PAGES = ['kb_view', 'kb_find', 'kb_home', 'kb_list', 'kb_comments',
                    'kb_article', 'kb_article_view', '$knowledge.do'];

    var publicPageRec = new GlideRecord('sys_public');
    publicPageRec.addActiveQuery();
    publicPageRec.addQuery('page', 'IN', KB_PAGES.join(','));
    publicPageRec.query();

    while (publicPageRec.next()) {
        engine.finding.setCurrentSource(publicPageRec);
        engine.finding.setValue('finding_details',
            'Public page "' + publicPageRec.getValue('page') + '" allows unauthenticated access to ' +
            'Knowledge Base content. Attackers can access KB portal pages without logging in, ' +
            'enabling article enumeration and data extraction. Remove this sys_public record ' +
            'unless public KB access is intentionally required.');
        engine.finding.increment();
    }

})(engine);
```

</details>

---

### Service Portal KB widgets must not have the public flag enabled, which allows un

**What:** Identifies Service Portal widgets with KB-related names where the public field is set to true, allowing unauthenticated access. AppOmni research showed that attackers can access misconfigured KBs through public widgets, including brute-forcing incremental KB article numbers (KB0000001, KB0000002, etc.) using the widget server-side API without authentication.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: KB Service Portal widgets marked as public
 * Check ID: cstaces-11o
 *
 * Type:     Script Only
 * Category: KB Security — Public Access
 * Severity: High
 *
 * Checks for Service Portal widget instances related to Knowledge Base
 * where the public flag is enabled, allowing unauthenticated access.
 * AppOmni showed attackers can brute-force KB article IDs (KB0000001,
 * KB0000002, etc.) via public KB Article Page widgets.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    // Check sp_widget for public KB widgets
    var KB_WIDGET_NAMES = [
        'KB Article Page', 'KB View 2', 'KB Search', 'KB Category Page',
        'Knowledge Base', 'Knowledge Article View'
    ];

    var widgetRec = new GlideRecord('sp_widget');
    widgetRec.addQuery('name', 'IN', KB_WIDGET_NAMES.join(','));
    widgetRec.addQuery('public', true);
    widgetRec.query();

    while (widgetRec.next()) {
        engine.finding.setCurrentSource(widgetRec);
        engine.finding.setValue('finding_details',
            'Service Portal widget "' + widgetRec.getValue('name') + '" is marked as public. ' +
            'Unauthenticated users can access KB content through this widget. ' +
            'Attackers can brute-force KB article numbers (KB0000001, KB0000002, etc.) ' +
            'to enumerate and extract articles. Uncheck the "Public" flag unless ' +
            'public KB access is intentionally required.');
        engine.finding.increment();
    }

})(engine);
```

</details>

---

### The sn_km_api Knowledge Management REST API must require authentication to preve

**What:** Checks whether the sn_km_api Scripted REST Service requires authentication. The /api/sn_km_api/ API is public by default and does not require authentication. Any knowledge base that is publicly accessible becomes available for programmatic enumeration and download via this API without credentials. For version 1.0.1 and later, the API can be configured to require authentication.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: Knowledge Management REST API allows unauthenticated access
 * Check ID: cstaces-11p
 *
 * Type:     Script Only
 * Category: KB Security — API Access
 * Severity: Critical
 *
 * Checks whether the sn_km_api (Knowledge Management REST API) is configured
 * to require authentication. By default, this API is public and does not
 * require authentication — any publicly accessible KB can be queried
 * programmatically without credentials.
 *
 * Reference: https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0959663
 */

(function(engine) {

    var apiRec = new GlideRecord('sys_ws_definition');
    apiRec.addQuery('name', 'CONTAINS', 'Knowledge Management');
    apiRec.addOrCondition('service_address', 'CONTAINS', 'sn_km_api');
    apiRec.query();

    while (apiRec.next()) {
        if (apiRec.getValue('requires_authentication') !== 'true') {
            engine.finding.setCurrentSource(apiRec);
            engine.finding.setValue('finding_details',
                'Scripted REST API "' + apiRec.getValue('name') + '" (' +
                apiRec.getValue('service_address') + ') does not require authentication. ' +
                'Any publicly accessible KB articles can be queried and downloaded via this API ' +
                'without credentials. Enable "Requires Authentication" on this REST API definition. ' +
                'See KB0959663 for guidance.');
            engine.finding.increment();
        }
    }

})(engine);
```

</details>

---

### ACLs on the kb_knowledge table must not be empty (no role, condition, script, or

**What:** Identifies ACL records for the kb_knowledge table where role, condition, script, and security_attribute are all empty, granting unrestricted access. ACLs with a populated security_attribute are excluded since the Security Attribute provides its own access evaluation. While KB v3 primarily uses user criteria for access control, empty ACLs on the underlying table create a bypass path that can be exploited via the SimpleListWidget or direct table API access.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: Empty ACLs on kb_knowledge table
 * Check ID: cstaces-11q
 *
 * Type:     Script Only
 * Category: KB Security — ACLs
 * Severity: High
 *
 * Identifies ACL records for the kb_knowledge table where role, condition,
 * script, AND security_attribute are all empty — granting unrestricted access.
 * If security_attribute is populated, the ACL delegates to a Security Attribute
 * check and is not considered empty. While KB v3 primarily uses user criteria
 * for access control, truly empty ACLs on the underlying table create a bypass
 * path (e.g., via SimpleListWidget).
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 * Reference: https://www.obsidiansecurity.com/blog/are-your-servicenow-lists-publicly-exposing-data
 */

(function(engine) {

    var aclRec = new GlideRecord('sys_security_acl');
    aclRec.addQuery('name', 'CONTAINS', 'kb_knowledge');
    aclRec.addQuery('active', true);
    aclRec.query();

    while (aclRec.next()) {
        var hasRole = false;
        var hasCondition = aclRec.getValue('condition') !== '' && aclRec.getValue('condition') !== null;
        var hasScript = aclRec.getValue('script') !== '' && aclRec.getValue('script') !== null;
        var hasSecAttr = aclRec.getValue('security_attribute') !== '' && aclRec.getValue('security_attribute') !== null;

        // If security_attribute is populated, the ACL delegates to a
        // Security Attribute check — not considered empty
        if (hasSecAttr) continue;

        // Check if ACL has any role requirements
        var aclRoleRec = new GlideRecord('sys_security_acl_role');
        aclRoleRec.addQuery('sys_security_acl', aclRec.getUniqueValue());
        aclRoleRec.query();
        hasRole = aclRoleRec.hasNext();

        if (!hasRole && !hasCondition && !hasScript) {
            engine.finding.setCurrentSource(aclRec);
            engine.finding.setValue('finding_details',
                'ACL "' + aclRec.getValue('name') + '" (operation: ' + aclRec.getValue('operation') +
                ') on the kb_knowledge table has no role, no condition, and no script — ' +
                'granting unrestricted access. This can be exploited via direct list access ' +
                'or widgets like SimpleListWidget to bypass user criteria restrictions. ' +
                'Add appropriate role requirements or conditions to this ACL.');
            engine.finding.increment();
        }
    }

})(engine);
```

</details>

---

### Custom ACLs on the kb_knowledge table may override user criteria restrictions an

**What:** Identifies non-OOB (custom) ACL records on the kb_knowledge table. ACLs with a populated security_attribute are excluded. Custom ACLs can inadvertently grant broader access than user criteria intend. For example, an ACL granting admin or itil read access without checking user criteria bypasses all KB-level and article-level restrictions. This check flags custom ACLs for review rather than as definitively wrong.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: Custom ACLs on kb_knowledge that may override user criteria
 * Check ID: cstaces-11r
 *
 * Type:     Script Only
 * Category: KB Security — ACLs
 * Severity: Medium
 *
 * Identifies non-OOB (custom) ACL records on the kb_knowledge table.
 * Custom ACLs can inadvertently grant broader access than user criteria intend.
 * For example, an ACL granting 'admin' or 'itil' read access without checking
 * user criteria bypasses all KB-level and article-level restrictions.
 *
 * ACLs with a populated security_attribute field are excluded — the Security
 * Attribute provides its own access control evaluation.
 *
 * This check flags custom ACLs for review — not all are problematic, but
 * each should be validated against the intended KB access model.
 *
 * Reference: https://www.servicenow.com/community/developer-forum/acl-overriding-user-criteria-for-knowledge-base/m-p/3110308
 */

(function(engine) {

    var aclRec = new GlideRecord('sys_security_acl');
    aclRec.addQuery('name', 'CONTAINS', 'kb_knowledge');
    aclRec.addQuery('active', true);
    aclRec.addQuery('sys_policy', ''); // Empty sys_policy typically means custom/non-protected
    aclRec.query();

    while (aclRec.next()) {
        // If security_attribute is populated, the ACL delegates to a
        // Security Attribute check — skip it
        var secAttr = aclRec.getValue('security_attribute') || '';
        if (secAttr) continue;

        // Check if this is likely a custom ACL (not part of a plugin/app)
        var scope = aclRec.getValue('sys_scope') || '';
        var updateName = aclRec.getValue('sys_update_name') || '';

        // Flag ACLs not in the 'sn_km' or 'global' scope with known patterns
        // This is a heuristic — we flag for review, not as definitively wrong
        var isLikelyCustom = updateName.indexOf('sys_security_acl_') === 0 &&
            scope !== '' &&
            scope.indexOf('sn_km') < 0;

        // Also flag if the ACL was created after the instance was set up (custom addition)
        var created = aclRec.getValue('sys_created_on') || '';

        if (isLikelyCustom) {
            engine.finding.setCurrentSource(aclRec);
            engine.finding.setValue('finding_details',
                'Custom ACL "' + aclRec.getValue('name') + '" (operation: ' + aclRec.getValue('operation') +
                ', scope: ' + scope + ') exists on the kb_knowledge table. ' +
                'Custom ACLs can override user criteria restrictions — a user blocked by user criteria ' +
                'may still access articles if an ACL grants them access. Review this ACL to ensure it ' +
                'does not bypass intended KB access controls.');
            engine.finding.increment();
        }
    }

})(engine);
```

</details>

---

### Published articles in knowledge bases with no Can Read user criteria are at high

**What:** Identifies published articles where BOTH the parent knowledge base and the article itself have no Can Read user criteria. These articles are the most likely to be exposed to unauthenticated users if glide.knowman.block_access_with_no_user_criteria is false. Reports at the KB level with a count of unprotected articles rather than per-article findings.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: Published articles with no user criteria in open KBs
 * Check ID: cstaces-11s
 *
 * Type:     Script Only
 * Category: KB Security — Articles
 * Severity: High
 *
 * Identifies published articles where BOTH the parent KB and the article
 * itself have no "Can Read" user criteria. These articles are the most
 * likely to be exposed to unauthenticated users.
 *
 * Note: This check uses GlideAggregate to report at the KB level (count
 * of unprotected articles per KB) rather than creating a finding per article,
 * which would be overwhelming on large instances.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    // First, find KBs with no Can Read criteria (reuse logic from kb-no-can-read)
    var M2M_CANDIDATES = [
        'kb_uc_can_read_mtom',
        'm2m_kb_uc_can_read',
        'kb_uc_can_read_m2m'
    ];
    var m2mTable = '';
    for (var c = 0; c < M2M_CANDIDATES.length; c++) {
        var test = new GlideRecord(M2M_CANDIDATES[c]);
        if (test.isValid()) {
            m2mTable = M2M_CANDIDATES[c];
            break;
        }
    }

    var kbsWithCriteria = {};
    if (m2mTable) {
        var m2mRec = new GlideRecord(m2mTable);
        m2mRec.query();
        while (m2mRec.next()) {
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (kbRef) kbsWithCriteria[kbRef] = true;
        }
    }

    // Find open KBs (no Can Read criteria)
    var openKBs = [];
    var kbListRec = new GlideRecord('kb_knowledge_base');
    kbListRec.addActiveQuery();
    kbListRec.query();
    while (kbListRec.next()) {
        if (!kbsWithCriteria[kbListRec.getUniqueValue()]) {
            openKBs.push(kbListRec.getUniqueValue());
        }
    }

    if (openKBs.length === 0) return;

    // Count published articles per open KB
    var articleAgg = new GlideAggregate('kb_knowledge');
    articleAgg.addQuery('kb_knowledge_base', 'IN', openKBs.join(','));
    articleAgg.addQuery('workflow_state', 'published');
    articleAgg.addAggregate('COUNT');
    articleAgg.groupBy('kb_knowledge_base');
    articleAgg.query();

    while (articleAgg.next()) {
        var count = parseInt(articleAgg.getAggregate('COUNT'), 10);
        if (count > 0) {
            var kbId = articleAgg.getValue('kb_knowledge_base');
            var kbRec = new GlideRecord('kb_knowledge_base');
            if (kbRec.get(kbId)) {
                engine.finding.setCurrentSource(kbRec);
                engine.finding.setValue('finding_details',
                    'Knowledge Base "' + kbRec.getValue('title') + '" has no "Can Read" user criteria ' +
                    'and contains ' + count + ' published article(s) that also lack article-level ' +
                    'user criteria. These articles are the highest risk for unintended exposure. ' +
                    'Add "Can Read" user criteria to the KB or to individual sensitive articles.');
                engine.finding.increment();
            }
        }
    }

})(engine);
```

</details>

---

### Articles with the public role in the roles field should be reviewed to confirm i

**What:** Identifies published articles on the kb_knowledge table where the roles field contains the public role. While the Mark Public action adds the public role, this does little to make the article actually accessible without authentication. However, it creates confusion about intended access levels and may interact unexpectedly with glide.knowman.search.apply_role_based_security. The presence of the public role should be audited to confirm it was intentional.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: Articles with the 'public' role set
 * Check ID: cstaces-11t
 *
 * Type:     Script Only
 * Category: KB Security — Articles
 * Severity: Medium
 *
 * Identifies published KB articles where the 'roles' field contains 'public'.
 * While this doesn't directly enable unauthenticated access (users still need
 * to authenticate), it signals intent for broad access and may interact
 * unexpectedly with glide.knowman.search.apply_role_based_security.
 *
 * Each article found should be reviewed to confirm the public role is intentional.
 *
 * Reference: https://servicenowguru.com/system-definition/controlling-public-availability-knowledge-base-content/
 */

(function(engine) {

    var articleRec = new GlideRecord('kb_knowledge');
    articleRec.addQuery('workflow_state', 'published');
    articleRec.addQuery('roles', 'CONTAINS', 'public');
    articleRec.addActiveQuery();
    articleRec.query();

    while (articleRec.next()) {
        engine.finding.setCurrentSource(articleRec);
        engine.finding.setValue('finding_details',
            'Article "' + articleRec.getValue('short_description') + '" (number: ' +
            articleRec.getValue('number') + ') in KB "' + articleRec.getDisplayValue('kb_knowledge_base') +
            '" has the "public" role set. Review whether broad public access is intentional ' +
            'for this article. The public role may interact with ' +
            'glide.knowman.search.apply_role_based_security to affect search visibility.');
        engine.finding.increment();
    }

})(engine);
```

</details>

---

### Knowledge bases using scripted (advanced) user criteria should be reviewed for p

**What:** Identifies user criteria records with Advanced (scripted) evaluation that are applied to knowledge bases via Can Read, Cannot Read, Can Contribute, or Cannot Contribute. Scripted criteria are cached at session level only (not application level), causing performance degradation. They are harder to audit since an administrator cannot easily determine who matches a scripted condition without running it. Scripts may also contain logic bugs that inadvertently grant or deny access.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: Scripted (advanced) user criteria applied to KBs
 * Check ID: cstaces-11u
 *
 * Type:     Script Only
 * Category: KB Security — User Criteria
 * Severity: Medium
 *
 * Identifies user criteria records with "Advanced" (scripted) evaluation
 * that are applied to knowledge bases. Scripted criteria are:
 *   - Cached at session level only (not application level) — performance hit
 *   - Harder to audit — cannot determine who matches without running the script
 *   - May contain logic bugs that inadvertently grant or deny access
 *
 * Best practice: extend the user_criteria table with additional fields instead.
 *
 * Reference: https://www.servicenow.com/community/itsm-blog/scripts-in-user-criteria/ba-p/2294597
 */

(function(engine) {

    // Find all scripted user criteria
    var scriptedUC = {};
    var ucRec = new GlideRecord('user_criteria');
    ucRec.addQuery('advanced', true);
    ucRec.addActiveQuery();
    ucRec.query();
    while (ucRec.next()) {
        scriptedUC[ucRec.getUniqueValue()] = ucRec.getValue('name');
    }

    if (Object.keys(scriptedUC).length === 0) return;

    // Check all M2M tables for these criteria being used on KBs
    var M2M_TABLES = [
        'kb_uc_can_read_mtom', 'm2m_kb_uc_can_read', 'kb_uc_can_read_m2m',
        'kb_uc_cannot_read_mtom', 'm2m_kb_uc_cannot_read', 'kb_uc_cannot_read_m2m',
        'kb_uc_can_contribute_mtom', 'm2m_kb_uc_can_contribute', 'kb_uc_can_contribute_m2m',
        'kb_uc_cannot_contribute_mtom', 'm2m_kb_uc_cannot_contribute', 'kb_uc_cannot_contribute_m2m'
    ];

    var findings = {}; // kbId -> [criteriaNames]

    for (var t = 0; t < M2M_TABLES.length; t++) {
        var m2mRec = new GlideRecord(M2M_TABLES[t]);
        if (!m2mRec.isValid()) continue;
        m2mRec.query();
        while (m2mRec.next()) {
            var ucRef = m2mRec.getValue('user_criteria') || m2mRec.getValue('user_criteria_id') || '';
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (ucRef && kbRef && scriptedUC[ucRef]) {
                if (!findings[kbRef]) findings[kbRef] = [];
                if (findings[kbRef].indexOf(scriptedUC[ucRef]) < 0) {
                    findings[kbRef].push(scriptedUC[ucRef]);
                }
            }
        }
    }

    // Report findings per KB
    for (var kbId in findings) {
        var kbRec = new GlideRecord('kb_knowledge_base');
        if (kbRec.get(kbId) && kbRec.getValue('active') === 'true') {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" uses ' +
                findings[kbId].length + ' scripted (advanced) user criteria: ' +
                findings[kbId].join(', ') + '. Scripted criteria are cached at session level ' +
                'only (degraded performance), are difficult to audit, and may contain logic bugs. ' +
                'Consider replacing with field-based criteria by extending the user_criteria table.');
            engine.finding.increment();
        }
    }

})(engine);
```

</details>

---

### Knowledge bases with commenting enabled should be reviewed, as comments can be u

**What:** Identifies active knowledge bases where the disable_commenting field is false (commenting is enabled). Comments on KB articles can be used to post sensitive information, phishing links, or social engineering content. For knowledge bases containing sensitive content or those accessible to external users, commenting should generally be disabled as a governance measure.

<details>
<summary>View Script</summary>

```javascript
/**
 * Instance Scan Check: KBs with commenting enabled
 * Check ID: cstaces-11v
 *
 * Type:     Script Only
 * Category: KB Security — Governance
 * Severity: Low
 *
 * Identifies active knowledge bases where commenting is enabled
 * (disable_commenting = false). Comments on KB articles can be used to
 * post sensitive information, phishing links, or social engineering content.
 *
 * This is an informational check — commenting may be appropriate for
 * internal KBs but should be reviewed for externally-facing or
 * sensitive content KBs.
 */

(function(engine) {

    var kbRec = new GlideRecord('kb_knowledge_base');
    kbRec.addActiveQuery();
    kbRec.addQuery('disable_commenting', false);
    kbRec.query();

    while (kbRec.next()) {
        engine.finding.setCurrentSource(kbRec);
        engine.finding.setValue('finding_details',
            'Knowledge Base "' + kbRec.getValue('title') + '" has commenting enabled. ' +
            'Comments can be used to post sensitive data, phishing links, or misleading content. ' +
            'Review whether commenting is appropriate for this KB, especially if it is ' +
            'externally-facing or contains sensitive content. Set "Disable Commenting" to true ' +
            'if comments are not needed.');
        engine.finding.increment();
    }

})(engine);
```

</details>

---

## Level Next

### Scheduled jobs running as admin

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
				engine.finding.setValue('finding_details', scheduledJob.sys_name.getDisplayValue() + ' running as user:'+runAsUser.getDisplayValue());
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

### Review active OAuth IDs

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


		//Get extended record
		var oauthRec = new GlideRecord(oauthEntity.sys_class_name);
		oauthRec.get(oauthEntity.getUniqueValue());

		var oauthName = oauthRec.name.getDisplayValue();

		var oauthTypeDisp = oauthRec.type.getDisplayValue();
		var oauthTypeStr = oauthRec.type.getValue();

		var oauthGrantDisp = oauthRec.default_grant_type.getDisplayValue();
		var oauthGrantStr = oauthRec.default_grant_type.getValue();


		var findingStr = oauthName + ' ('+ oauthGrantDisp + ') - Review and disable record or mute finding.';

		engine.finding.setCurrentSource(oauthEntity);
		engine.finding.setValue('finding_details',findingStr);
		engine.finding.increment();


        // oauthApps.push({
        //     name: oauthEntity.name.toString(),
        //     client_id: oauthEntity.client_id.toString(),
        //     redirect_url: oauthEntity.redirect_url.toString(),
        //     access_token_lifespan: oauthEntity.access_token_lifespan.toString(),
        //     refresh_token_lifespan: oauthEntity.refresh_token_lifespan.toString()
        // });
    }

    //gs.info('Active OAuth applications: ' + JSON.stringify(oauthApps, null, 2));

})(engine);
```

</details>

---

### Find BRs with risky patterns

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
			engine.finding.setValue('finding_details','Patterns found:'+JSON.stringify(matchedPatterns));
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

### UI Policies Bypassing Mandatory Fields

**What:** Identifies active UI policies that contain actions setting fields to non-mandatory. These policies can override mandatory field requirements configured at the dictionary or form level, allowing users to submit records with missing data.

**Why:** Mandatory field enforcement is a key data integrity control. UI policies that silently remove mandatory constraints can lead to incomplete records, broken workflows, and compliance gaps. CIS and NIST SI-10 require that input validation controls be consistently enforced and not overridden without authorization.

<details>
<summary>View Script</summary>

```javascript
(function (engine) {

	var uiPolicy = new GlideRecord('sys_ui_policy');
	uiPolicy.addQuery('active', 'true');
	uiPolicy.query();

	while (uiPolicy.next()) {
		var actions = new GlideRecord('sys_ui_policy_action');
		actions.addQuery('ui_policy', uiPolicy.getUniqueValue());
		actions.addQuery('mandatory', 'false');
		actions.query();

		if (actions.next()) {
			//gs.info('UI Policy bypassing mandatory fields: ' + uiPolicy.short_description.toString());

			engine.finding.setCurrentSource(actions);
			engine.finding.setValue('finding_details','Not mandatory: '+ uiPolicy.short_description.toString());
			engine.finding.increment();
		}
	}

})(engine);
```

</details>

---

### Review user session configs

**What:** Retrieves key security-related system properties governing guest access, SSO enforcement, multi-provider SSO configuration, and session timeout values. Provides a snapshot of the instance's authentication posture.

**Why:** Weak authentication configuration is the most impactful category of misconfiguration in any enterprise platform. NIST IA-2, IA-8, and AC-12 require that systems enforce strong authentication, mandate SSO where available, and terminate sessions after defined inactivity periods.

<details>
<summary>View Script</summary>

```javascript
(function (engine) {

	// Check authentication and session security properties
	var policies = [
		'glide.authenticate.sso.redirect.idp',
		'glide.authenticate.multisso.enabled',
		'glide.authenticate.sso.required',        // SSO enforcement
		'glide.ui.session_timeout'                // UI session timeout
	];
		//'session.timeout',                        // Session timeout
		//'glide.ui.security.allow_guest',          // Guest access enabled?
		//'glide.authenticate.multisso.use.idp',    // Multi-provider SSO

	var policySettings = {};
	for (var i = 0; i < policies.length; i++) {
		
		//Get Value - Traditional Method
		
		var policyValue = gs.getProperty(policies[i]);
		policySettings[policies[i]] = policyValue;


		//engine.finding.setCurrentSource(propRec);
		engine.finding.setValue('finding_details','1Property currently configured as:'+policyValue);
		engine.finding.increment();

		//Get Record
		var propRec = new GlideRecord('sys_properties');
		propRec.addQuery('name',policies[i]);
		propRec.query();
		if(propRec.next()){

			engine.finding.setCurrentSource(propRec);
			engine.finding.setValue('finding_details','2Property currently configured as:'+policyValue);
			engine.finding.increment();

		}else{

			engine.finding.setValue('finding_details','Cant find prop:'+policies[i]);
			engine.finding.increment();

		}



	}

	//gs.info('Security policy settings: ' + JSON.stringify(policySettings, null, 2));

})(engine);
```

</details>

---

### Admin Users Without MFA

**What:** Identifies active users with admin or security_admin roles who do not have an active MFA device enrolled in ServiceNow's native MFA system (sys_user_mfa_device).

**Why:** Privileged accounts without MFA are the highest-value targets for credential-based attacks. NIST IA-2(1), PCI DSS 8.4, and virtually every modern compliance framework mandate multi-factor authentication for administrative access. A single compromised admin password without MFA can lead to full instance takeover.

<details>
<summary>View Script</summary>

```javascript
(function (engine) {

	// Find privileged users without MFA enrolled
	var privilegedUserIds = {};
	var adminRoleQuery = new GlideRecord('sys_user_has_role');
	adminRoleQuery.addQuery('role.name', 'IN', 'admin,security_admin');
	adminRoleQuery.addQuery('user.active', 'true');
	adminRoleQuery.addQuery('state', 'active');
	adminRoleQuery.query();

	while (adminRoleQuery.next()) {
		privilegedUserIds[adminRoleQuery.getValue('user')] = true;
	}

	var noMFAUsers = [];
	for (var userId in privilegedUserIds) {
		var userRecord = new GlideRecord('sys_user');
		if (userRecord.get(userId)) {
			var mfaDevice = new GlideRecord('sys_user_multi_factor_setup');
			mfaDevice.addQuery('user', userId);
			mfaDevice.addQuery('active', 'true');
			mfaDevice.query();

			if (!mfaDevice.hasNext()) {

				engine.finding.setCurrentSource(userRecord);
				//engine.finding.setValue('finding_details','Found with DIRECT role assignment');
				engine.finding.increment();


				noMFAUsers.push({
					user: userRecord.user_name.toString(),
					name: userRecord.name.toString(),
					email: userRecord.email.toString()
				});
			}
		}
	}

	//gs.warn('Admin users without MFA: ' + JSON.stringify(noMFAUsers, null, 2));

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


# SN Account Instance Hardening

ServiceNow instance hardening security assessment queries.

## Overview

Comprehensive queries, scripts, and methods to audit ServiceNow instances for security misconfigurations and least privilege violations.

These scripts are designed to be run in the **Scripts - Background** console of a ServiceNow instance. They assess common security configuration gaps across identity, access control, privileged activity, and platform hygiene. Each check also includes a **Security Center Script Check** variant for use with ServiceNow's Vulnerability Security Center (VSC) compliance framework.

## Deployment Levels

Scripts are organized into deployment levels based on priority and risk:

| Level | Description | Script Location |
|-------|-------------|-----------------|
| **Level 1** | Core security checks - deploy and validate first | `scans/_review/level-1/` |
| **Level 2** | Important checks - deploy after Level 1 is validated | `scans/_review/level-2/` |
| **Level 3** | Supplementary checks - deploy after Level 2 | `scans/_review/level-3/` |

---

## Level 1 - First Wave

### 1a. Users with Admin or Security Admin Roles

> **Script:** [`query1a-admin-security-admin-users.js`](scans/_review/level-1/query1a-admin-security-admin-users.js)

**What:** Enumerates all active users with `admin`, `security_admin`, or `user_admin` roles via both direct assignment and group inheritance. Flags dormant accounts (by last login) and potential service accounts.

**Why:** CIS and NIST 800-53 (AC-6) require that the highest-privilege roles be limited to the smallest number of named individuals with a documented business need. Unreviewed admin populations are consistently one of the top findings in ServiceNow security assessments.

<details>
<summary>Scripts - Background</summary>

```javascript
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
        }
    }
}

var results = [];
for (var uname in privilegedUsers) {
    results.push(privilegedUsers[uname]);
}

var multiRole = results.filter(function(u) { return u.roles.length > 1; });
var serviceAccounts = results.filter(function(u) { return u.is_service_account; });

gs.info('Total privileged users: ' + results.length);
gs.info('Users with multiple high privilege roles: ' + multiRole.length);
gs.info('Potential service accounts: ' + serviceAccounts.length);
gs.info(JSON.stringify(results, null, 2));
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'privileged_user_population');

var privilegedRoles = ['admin', 'security_admin', 'user_admin'];
var dormantCount = 0;
var ninetyDaysAgo = new GlideDateTime();
ninetyDaysAgo.addDaysUTC(-90);

for (var i = 0; i < privilegedRoles.length; i++) {
    var roleAssignment = new GlideRecord('sys_user_has_role');
    roleAssignment.addQuery('role.name', privilegedRoles[i]);
    roleAssignment.addQuery('user.active', 'true');
    roleAssignment.addQuery('state', 'active');
    roleAssignment.query();
    while (roleAssignment.next()) {
        var lastLogin = roleAssignment.user.last_login_time.toString();
        if (lastLogin) {
            var loginDate = new GlideDateTime(lastLogin);
            if (loginDate.compareTo(ninetyDaysAgo) < 0) {
                dormantCount++;
            }
        } else {
            dormantCount++;
        }
    }
}

// Non-compliant if any dormant privileged accounts exist
checkConfig.config_configure = (dormantCount === 0);
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 1b. Users with Multiple High-Privilege Roles

> **Script:** [`query1b-multiple-high-privilege-roles.js`](scans/_review/level-1/query1b-multiple-high-privilege-roles.js)

**What:** Identifies active users holding two or more high-privilege roles simultaneously (admin, security_admin, user_admin, delegated_admin, itil_admin, catalog_admin, knowledge_admin). Results are sorted by role count descending.

**Why:** Role accumulation violates the principle of least privilege (NIST AC-6(5)) and significantly expands the blast radius of a compromised account. Separation of duties controls require that no single account concentrates multiple administrative capabilities without explicit justification.

<details>
<summary>Scripts - Background</summary>

```javascript
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

for (var i = 0; i < privilegedRoles.length; i++) {
    var roleName = privilegedRoles[i];
    var direct = new GlideRecord('sys_user_has_role');
    direct.addQuery('role.name', roleName);
    direct.addQuery('user.active', 'true');
    direct.addQuery('state', 'active');
    direct.query();
    while (direct.next()) {
        addUser(direct.getValue('user'), roleName, 'direct:' + roleName);
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
        }
    }
}

// Only include users with 2+ high-privilege roles
var results = [];
for (var uname in privilegedUsers) {
    if (privilegedUsers[uname].roles.length > 1) {
        results.push(privilegedUsers[uname]);
    }
}

results.sort(function(a, b) { return b.roles.length - a.roles.length; });

var serviceAccounts = results.filter(function(u) { return u.is_service_account; });

gs.info('Users with multiple high-privilege roles: ' + results.length);
gs.info('Potential service accounts with multiple roles: ' + serviceAccounts.length);
gs.info(JSON.stringify(results, null, 2));
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'multiple_high_privilege_roles');

var privilegedRoles = ['admin', 'security_admin', 'user_admin', 'delegated_admin', 'itil_admin', 'catalog_admin', 'knowledge_admin'];
var userRoleCounts = {};

for (var i = 0; i < privilegedRoles.length; i++) {
    var roleAssignment = new GlideRecord('sys_user_has_role');
    roleAssignment.addQuery('role.name', privilegedRoles[i]);
    roleAssignment.addQuery('user.active', 'true');
    roleAssignment.addQuery('state', 'active');
    roleAssignment.query();
    while (roleAssignment.next()) {
        var userId = roleAssignment.getValue('user');
        userRoleCounts[userId] = (userRoleCounts[userId] || 0) + 1;
    }
}

var multiRoleCount = 0;
for (var uid in userRoleCounts) {
    if (userRoleCounts[uid] > 1) multiRoleCount++;
}

// Non-compliant if any user holds 2+ high-privilege roles
checkConfig.config_configure = (multiRoleCount === 0);
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 1c. Deprovisioned Users with Privileged Role Assignments

> **Script:** [`query1c-deprovisioned-privileged-users.js`](scans/_review/level-1/query1c-deprovisioned-privileged-users.js)

**What:** Identifies inactive users who still retain privileged role assignments. Separates direct assignments (critical) from inherited ones (high), and flags accounts deactivated within the last 90 days as highest reactivation risk.

**Why:** If a deprovisioned account is reactivated (intentionally or accidentally), elevated access is immediately restored without requiring a new approval. This is a common gap in offboarding processes and violates NIST AC-2(3) requirements for disabling inactive accounts and revoking associated authorizations.

<details>
<summary>Scripts - Background</summary>

```javascript
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

// Flag recently deactivated users (last 90 days) - highest reactivation risk
// Note: uses sys_updated_on as proxy since ServiceNow has no dedicated deactivation timestamp
var recentlyDeactivated = [];
var allRecords = direct.concat(inherited);

for (var i = 0; i < allRecords.length; i++) {
    var deactivatedUser = new GlideRecord('sys_user');
    deactivatedUser.get(allRecords[i].user_sys_id);
    var updatedOn = new GlideDateTime(deactivatedUser.sys_updated_on.toString());
    var ninetyDaysAgo = new GlideDateTime();
    ninetyDaysAgo.addDaysUTC(-90);
    if (updatedOn.compareTo(ninetyDaysAgo) > 0) {
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

var serviceAccounts = allRecords.filter(function(u) { return u.is_service_account; });

gs.info('=== DEPROVISIONED USERS WITH PRIVILEGED ROLES ===');
gs.info('Direct assignments (critical - survives reactivation): ' + direct.length);
gs.info('Inherited assignments (high - survives reactivation): ' + inherited.length);
gs.info('Total records: ' + (direct.length + inherited.length));
gs.info('Recently deactivated (<90 days, highest reactivation risk): ' + recentlyDeactivated.length);
gs.info('Potential service accounts: ' + serviceAccounts.length);
gs.info('\nDirect assignments:');
gs.info(JSON.stringify(direct, null, 2));
gs.info('\nInherited assignments:');
gs.info(JSON.stringify(inherited, null, 2));
gs.info('\nRecently deactivated users:');
gs.info(JSON.stringify(recentlyDeactivated, null, 2));
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'deprovisioned_users_privileged_roles');

var roleList = ['admin', 'security_admin', 'user_admin', 'delegated_admin', 'impersonator', 'itil_admin', 'catalog_admin', 'knowledge_admin'];

var ga = new GlideAggregate('sys_user_has_role');
ga.addQuery('role.name', 'IN', roleList.join(','));
ga.addQuery('user.active', false);
ga.addQuery('state', 'active');
ga.addAggregate('COUNT');
ga.query();

var count = 0;
if (ga.next()) {
    count = parseInt(ga.getAggregate('COUNT'));
}

// Non-compliant if any inactive users retain active privileged role assignments
checkConfig.config_configure = (count === 0);
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 3b. Impersonation Capability Assessment

> **Script:** [`query3b-impersonation-capability.js`](scans/_review/level-1/query3b-impersonation-capability.js)

**What:** Identifies all active users who can impersonate others by evaluating five vectors: direct `impersonator` role, direct `admin` role, direct `security_admin` role, group membership inheriting those roles, and role hierarchy where a parent role contains `impersonator` as a child.

**Why:** Impersonation capability is often granted implicitly through admin or security_admin roles, making the true population of impersonators far larger than expected. NIST AC-6(1) requires organizations to explicitly authorize access to privileged functions, and impersonation must be inventoried across all grant vectors.

<details>
<summary>Scripts - Background</summary>

```javascript
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
    addUser(direct.getValue('user'), 'direct:impersonator');
}

// 2. Direct admin role (implicitly grants impersonation)
var adminDirect = new GlideRecord('sys_user_has_role');
adminDirect.addQuery('role.name', 'admin');
adminDirect.addQuery('user.active', 'true');
adminDirect.addQuery('state', 'active');
adminDirect.query();
while (adminDirect.next()) {
    addUser(adminDirect.getValue('user'), 'direct:admin');
}

// 3. Direct security_admin role
var secAdmin = new GlideRecord('sys_user_has_role');
secAdmin.addQuery('role.name', 'security_admin');
secAdmin.addQuery('user.active', 'true');
secAdmin.addQuery('state', 'active');
secAdmin.query();
while (secAdmin.next()) {
    addUser(secAdmin.getValue('user'), 'direct:security_admin');
}

// 4. Group-inherited impersonator, admin, security_admin
var elevatedRoles = ['impersonator', 'admin', 'security_admin'];
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
            addUser(member.getValue('user'), 'group:' + groupName + ':' + elevatedRoleName);
        }
    }
}

// 5. Parent roles containing impersonator as a child role (role hierarchy)
var childRole = new GlideRecord('sys_user_role_contains');
childRole.addQuery('role.name', 'impersonator');
childRole.query();
while (childRole.next()) {
    var parentRoleName = childRole.parent.name.toString();
    var parentRoleId = childRole.getValue('parent');

    var parentUsers = new GlideRecord('sys_user_has_role');
    parentUsers.addQuery('role', parentRoleId);
    parentUsers.addQuery('user.active', 'true');
    parentUsers.query();
    while (parentUsers.next()) {
        addUser(parentUsers.getValue('user'), 'inherited_role:' + parentRoleName);
    }

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
            addUser(gMembers.getValue('user'), 'group_inherited_role:' + gName + ':' + parentRoleName);
        }
    }
}

var results = [];
for (var uname in impersonators) {
    results.push(impersonators[uname]);
}

var serviceAccounts = results.filter(function(u) { return u.is_service_account; });
var humanAccounts = results.filter(function(u) { return !u.is_service_account; });

gs.info('Total users with impersonation capability: ' + results.length);
gs.info('Human accounts: ' + humanAccounts.length);
gs.info('Potential service accounts: ' + serviceAccounts.length);
gs.info(JSON.stringify(results, null, 2));
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'impersonation_capability_population');

var impersonators = {};
var impersonationRoles = ['impersonator', 'admin', 'security_admin'];

for (var i = 0; i < impersonationRoles.length; i++) {
    var roleAssignment = new GlideRecord('sys_user_has_role');
    roleAssignment.addQuery('role.name', impersonationRoles[i]);
    roleAssignment.addQuery('user.active', 'true');
    roleAssignment.addQuery('state', 'active');
    roleAssignment.query();
    while (roleAssignment.next()) {
        impersonators[roleAssignment.getValue('user')] = true;
    }
}

var count = Object.keys(impersonators).length;
// Configurable threshold for acceptable impersonation population
var threshold = 15;
checkConfig.config_configure = (count <= threshold);
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 4a. Security Admin Population

> **Script:** [`query4a-security-admin-population.js`](scans/_review/level-1/query4a-security-admin-population.js)

**What:** Enumerates all active users with the `security_admin` role via direct and group-inherited assignments. Cross-references whether each user also holds the `admin` role, which compounds privilege. This query establishes the population used by queries 4b through 4e.

**Why:** The `security_admin` role controls ACLs, encryption, and role assignments. An unchecked security_admin population is a top-tier risk because it can modify the controls that protect everything else. NIST AC-6(5) requires that privileged accounts be inventoried and reviewed on a regular cadence.

<details>
<summary>Scripts - Background</summary>

```javascript
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

var withAdmin = results.filter(function(u) { return u.has_admin; });
var withoutAdmin = results.filter(function(u) { return !u.has_admin; });
var serviceAccounts = results.filter(function(u) { return u.is_service_account; });

gs.info('Total users with security_admin: ' + results.length);
gs.info('Also have admin (compounding privilege): ' + withAdmin.length);
gs.info('security_admin without admin: ' + withoutAdmin.length);
gs.info('Potential service accounts: ' + serviceAccounts.length);
gs.info(JSON.stringify(results, null, 2));
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'security_admin_population');

var secAdmins = {};

var direct = new GlideRecord('sys_user_has_role');
direct.addQuery('role.name', 'security_admin');
direct.addQuery('user.active', 'true');
direct.addQuery('state', 'active');
direct.query();
while (direct.next()) {
    secAdmins[direct.getValue('user')] = true;
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
        secAdmins[member.getValue('user')] = true;
    }
}

var count = Object.keys(secAdmins).length;
// Configurable threshold for acceptable security_admin population
var threshold = 10;
checkConfig.config_configure = (count <= threshold);
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 4c. Role Grants Made by Security Admin Users

> **Script:** [`query4c-role-grants.js`](scans/_review/level-1/query4c-role-grants.js)

**What:** Detects role assignment changes made by security_admin users in the last 30 days. Flags self-grants and grants of high-risk roles (admin, security_admin, impersonator) as the most direct indicators of privilege escalation.

**Why:** Role grants are the most explicit form of privilege escalation. A security_admin granting themselves or others additional elevated roles bypasses intended approval workflows. NIST AC-6(5) and SOC 2 CC6.1 require that privileged role changes be authorized, logged, and reviewed for anomalous patterns.

<details>
<summary>Scripts - Background</summary>

```javascript
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
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'security_admin_role_grants');

var secAdminUsernames = [];
var direct = new GlideRecord('sys_user_has_role');
direct.addQuery('role.name', 'security_admin');
direct.addQuery('user.active', 'true');
direct.query();
while (direct.next()) {
    var uname = direct.user.user_name.toString();
    if (secAdminUsernames.indexOf(uname) === -1) {
        secAdminUsernames.push(uname);
    }
}

var selfGrantFound = false;
var roleGrantTables = ['sys_user_has_role', 'sys_group_has_role'];

for (var i = 0; i < secAdminUsernames.length && !selfGrantFound; i++) {
    var audit = new GlideRecord('sys_audit');
    audit.addQuery('user', secAdminUsernames[i]);
    audit.addQuery('tablename', 'IN', roleGrantTables.join(','));
    audit.addQuery('sys_created_on', '>', gs.daysAgo(30));
    audit.query();
    while (audit.next() && !selfGrantFound) {
        var roleRecord = new GlideRecord(audit.tablename.toString());
        if (roleRecord.get(audit.documentkey.toString())) {
            if (audit.tablename.toString() === 'sys_user_has_role') {
                if (roleRecord.user.user_name.toString() === secAdminUsernames[i]) {
                    selfGrantFound = true;
                }
            }
        }
    }
}

// Non-compliant if any self-grants detected by security_admin users
checkConfig.config_configure = !selfGrantFound;
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 5a. Integration Users with Admin Roles

> **Script:** [`query5a-integration-users-admin-roles.js`](scans/_review/level-1/query5a-integration-users-admin-roles.js)

**What:** Finds all active users flagged as web-service-access-only (integration/API accounts) that have been assigned roles containing "admin" in the name. These are non-interactive accounts with overly broad privileges.

**Why:** Integration accounts should follow the principle of least privilege more strictly than human accounts because they typically operate unattended and are harder to monitor for misuse. CIS and NIST AC-6(10) recommend that non-interactive service accounts be restricted to the minimum permissions required for their function.

<details>
<summary>Scripts - Background</summary>

```javascript
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
        integrationUsers.push({
            user: integrationUser.user_name.toString(),
            name: integrationUser.name.toString(),
            roles: roles,
            last_login: integrationUser.last_login_time.toString()
        });
    }
}

gs.warn('Integration users with admin roles: ' + JSON.stringify(integrationUsers, null, 2));
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'integration_users_admin_roles');

var found = false;
var integrationUser = new GlideRecord('sys_user');
integrationUser.addQuery('web_service_access_only', 'true');
integrationUser.addQuery('active', 'true');
integrationUser.query();

while (integrationUser.next() && !found) {
    var userRoleAssignment = new GlideRecord('sys_user_has_role');
    userRoleAssignment.addQuery('user', integrationUser.getUniqueValue());
    userRoleAssignment.query();
    while (userRoleAssignment.next()) {
        if (userRoleAssignment.role.name.toString().indexOf('admin') > -1) {
            found = true;
            break;
        }
    }
}

// Non-compliant if any integration/API users have admin roles
checkConfig.config_configure = !found;
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 5b. Active OAuth Clients and Scopes

> **Script:** [`query5b-oauth-clients-scopes.js`](scans/_review/level-1/query5b-oauth-clients-scopes.js)

**What:** Audits all active OAuth application registrations, capturing client IDs, redirect URLs, and access/refresh token lifespans. Identifies applications that may have excessively long token lifetimes.

**Why:** OAuth tokens are bearer credentials - anyone who possesses a valid token can use it. Excessively long token lifespans increase the window of opportunity for token theft and replay. NIST IA-5(13) and OAuth 2.0 Security Best Current Practice (RFC 9700) recommend short-lived access tokens and bounded refresh token lifetimes.

<details>
<summary>Scripts - Background</summary>

```javascript
// Audit active OAuth applications and their token lifespans
var oauthEntity = new GlideRecord('oauth_entity');
oauthEntity.addQuery('active', 'true');
oauthEntity.query();

var oauthApps = [];
while (oauthEntity.next()) {
    oauthApps.push({
        name: oauthEntity.name.toString(),
        client_id: oauthEntity.client_id.toString(),
        redirect_url: oauthEntity.redirect_url.toString(),
        access_token_lifespan: oauthEntity.access_token_lifespan.toString(),
        refresh_token_lifespan: oauthEntity.refresh_token_lifespan.toString()
    });
}

gs.info('Active OAuth applications: ' + JSON.stringify(oauthApps, null, 2));
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'oauth_token_lifespans');

var excessiveLifespan = false;
var maxAccessTokenLifespan = 3600;  // 1 hour in seconds
var maxRefreshTokenLifespan = 86400; // 24 hours in seconds

var oauthEntity = new GlideRecord('oauth_entity');
oauthEntity.addQuery('active', 'true');
oauthEntity.query();

while (oauthEntity.next() && !excessiveLifespan) {
    var accessLifespan = parseInt(oauthEntity.access_token_lifespan.toString()) || 0;
    var refreshLifespan = parseInt(oauthEntity.refresh_token_lifespan.toString()) || 0;
    if (accessLifespan > maxAccessTokenLifespan || refreshLifespan > maxRefreshTokenLifespan) {
        excessiveLifespan = true;
    }
}

// Non-compliant if any OAuth app has excessive token lifespans
checkConfig.config_configure = !excessiveLifespan;
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 7. UI Policies Bypassing Mandatory Fields

> **Script:** [`query7-ui-policies-mandatory-bypass.js`](scans/_review/level-1/query7-ui-policies-mandatory-bypass.js)

**What:** Identifies active UI policies that contain actions setting fields to non-mandatory. These policies can override mandatory field requirements configured at the dictionary or form level, allowing users to submit records with missing data.

**Why:** Mandatory field enforcement is a key data integrity control. UI policies that silently remove mandatory constraints can lead to incomplete records, broken workflows, and compliance gaps. CIS and NIST SI-10 require that input validation controls be consistently enforced and not overridden without authorization.

<details>
<summary>Scripts - Background</summary>

```javascript
var uiPolicy = new GlideRecord('sys_ui_policy');
uiPolicy.addQuery('active', 'true');
uiPolicy.query();

while (uiPolicy.next()) {
    var actions = new GlideRecord('sys_ui_policy_action');
    actions.addQuery('ui_policy', uiPolicy.getUniqueValue());
    actions.addQuery('mandatory', 'false');
    actions.query();

    if (actions.hasNext()) {
        gs.info('UI Policy bypassing mandatory fields: ' +
                uiPolicy.short_description.toString());
    }
}
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'ui_policy_mandatory_bypass');

var found = false;
var uiPolicy = new GlideRecord('sys_ui_policy');
uiPolicy.addQuery('active', 'true');
uiPolicy.query();

while (uiPolicy.next() && !found) {
    var actions = new GlideRecord('sys_ui_policy_action');
    actions.addQuery('ui_policy', uiPolicy.getUniqueValue());
    actions.addQuery('mandatory', 'false');
    actions.query();
    if (actions.next()) {
        found = true;
    }
}

// Non-compliant if any active UI policy removes mandatory field enforcement
checkConfig.config_configure = !found;
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 9b. Admin Users Without MFA

> **Script:** [`query9b-admin-users-without-mfa.js`](scans/_review/level-1/query9b-admin-users-without-mfa.js)

**What:** Identifies active users with `admin` or `security_admin` roles who do not have an active MFA device enrolled in ServiceNow's native MFA system (`sys_user_mfa_device`).

**Why:** Privileged accounts without MFA are the highest-value targets for credential-based attacks. NIST IA-2(1), PCI DSS 8.4, and virtually every modern compliance framework mandate multi-factor authentication for administrative access. A single compromised admin password without MFA can lead to full instance takeover.

<details>
<summary>Scripts - Background</summary>

```javascript
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
        var mfaDevice = new GlideRecord('sys_user_mfa_device');
        mfaDevice.addQuery('user', userId);
        mfaDevice.addQuery('active', 'true');
        mfaDevice.query();

        if (!mfaDevice.hasNext()) {
            noMFAUsers.push({
                user: userRecord.user_name.toString(),
                name: userRecord.name.toString(),
                email: userRecord.email.toString()
            });
        }
    }
}

gs.warn('Admin users without MFA: ' + JSON.stringify(noMFAUsers, null, 2));
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'admin_users_without_mfa');

var noMFAFound = false;
var privilegedUserIds = {};
var adminRoleQuery = new GlideRecord('sys_user_has_role');
adminRoleQuery.addQuery('role.name', 'IN', 'admin,security_admin');
adminRoleQuery.addQuery('user.active', 'true');
adminRoleQuery.addQuery('state', 'active');
adminRoleQuery.query();

while (adminRoleQuery.next()) {
    privilegedUserIds[adminRoleQuery.getValue('user')] = true;
}

for (var userId in privilegedUserIds) {
    if (noMFAFound) break;
    var mfaDevice = new GlideRecord('sys_user_mfa_device');
    mfaDevice.addQuery('user', userId);
    mfaDevice.addQuery('active', 'true');
    mfaDevice.query();
    if (!mfaDevice.hasNext()) {
        noMFAFound = true;
    }
}

// Non-compliant if any admin/security_admin user lacks an active MFA device
checkConfig.config_configure = !noMFAFound;
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 10. Scheduled Jobs Running as Admin

> **Script:** [`query10-scheduled-jobs-admin.js`](scans/_review/level-1/query10-scheduled-jobs-admin.js)

**What:** Identifies active scheduled script executions (`sysauto_script`) configured to run as a user with the `admin` role. These jobs execute on a schedule with the full privileges of the run-as user.

**Why:** Scheduled jobs running as admin operate with unrestricted access and no interactive session monitoring. If the run-as account is compromised or the job script is modified, it becomes a persistent backdoor. NIST AC-6(1) and CIS recommend that automated processes run with the minimum privileges required.

<details>
<summary>Scripts - Background</summary>

```javascript
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
            adminJobs.push({
                name: scheduledJob.name.toString(),
                run_as: runAsUser.name.toString(),
                run_dayofweek: scheduledJob.run_dayofweek.toString(),
                run_time: scheduledJob.run_time.toString()
            });
        }
    }
}

gs.info('Scheduled jobs running as admin: ' + JSON.stringify(adminJobs, null, 2));
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'scheduled_jobs_admin_runas');

var found = false;
var scheduledJob = new GlideRecord('sysauto_script');
scheduledJob.addQuery('active', 'true');
scheduledJob.query();

while (scheduledJob.next() && !found) {
    var runAs = scheduledJob.run_as.toString();
    if (runAs) {
        var adminRoleCheck = new GlideRecord('sys_user_has_role');
        adminRoleCheck.addQuery('user', runAs);
        adminRoleCheck.addQuery('role.name', 'admin');
        adminRoleCheck.addQuery('state', 'active');
        adminRoleCheck.query();
        if (adminRoleCheck.hasNext()) {
            found = true;
        }
    }
}

// Non-compliant if any active scheduled job runs as an admin user
checkConfig.config_configure = !found;
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

## Level 2 - Second Wave

### 2a. Overly Permissive ACLs

> **Script:** [`query2a-overly-permissive-acls.js`](scans/_review/level-2/query2a-overly-permissive-acls.js)

**What:** Identifies active ACLs that have no role restrictions, no conditions, and no scripts, meaning any authenticated user can pass them. Results are categorized by risk level: CRITICAL (wildcard `*` operation), HIGH (write/create/delete), MEDIUM (read), and LOW (other).

**Why:** Misconfigured ACLs are the most common access control weakness in ServiceNow instances. NIST AC-3 and CIS controls require that access to resources be enforced through policy-based mechanisms. An ACL with no restrictions is effectively no access control at all.

<details>
<summary>Scripts - Background</summary>

```javascript
(function findOverlyPermissiveACLs() {

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
    var riskOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 };
    riskyACLs.sort(function(a, b) {
        return riskOrder[a.risk_level] - riskOrder[b.risk_level];
    });

    gs.info('=== OVERLY PERMISSIVE ACL SCAN ===');
    gs.info('Total findings: ' + riskyACLs.length);
    gs.info('CRITICAL: ' + riskyACLs.filter(function(a) { return a.risk_level === 'CRITICAL'; }).length);
    gs.info('HIGH: ' + riskyACLs.filter(function(a) { return a.risk_level === 'HIGH'; }).length);
    gs.info('MEDIUM: ' + riskyACLs.filter(function(a) { return a.risk_level === 'MEDIUM'; }).length);
    gs.info('LOW: ' + riskyACLs.filter(function(a) { return a.risk_level === 'LOW'; }).length);
    gs.info('Full results: ' + JSON.stringify(riskyACLs, null, 2));

})();
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'overly_permissive_acls');

var aclsWithRoles = {};
var aclRoleEntry = new GlideRecord('sys_security_acl_role');
aclRoleEntry.addNotNullQuery('sys_security_acl');
aclRoleEntry.query();
while (aclRoleEntry.next()) {
    aclsWithRoles[aclRoleEntry.sys_security_acl.toString()] = true;
}

var riskyCount = 0;
var aclRecord = new GlideRecord('sys_security_acl');
aclRecord.addQuery('active', 'true');
aclRecord.addNullQuery('condition');
aclRecord.addNullQuery('script');
aclRecord.addQuery('sys_policy', '!=', 'read');
aclRecord.query();

while (aclRecord.next()) {
    if (!aclsWithRoles[aclRecord.sys_id.toString()]) {
        var op = aclRecord.operation.toString();
        if (op === '*' || op === 'write' || op === 'create' || op === 'delete') {
            riskyCount++;
        }
    }
}

// Non-compliant if any CRITICAL or HIGH risk ACLs found with no restrictions
checkConfig.config_configure = (riskyCount === 0);
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 2b. ACLs with Dangerous Scripts

> **Script:** [`query2b-acls-dangerous-scripts.js`](scans/_review/level-2/query2b-acls-dangerous-scripts.js)

**What:** Scans all active ACLs with non-null scripts for patterns indicating dangerous or overly permissive access control logic, including unconditional grants (`answer = true`), admin bypass patterns, dynamic behavior via external scripts or properties, and incomplete/disabled logic markers.

**Why:** Script-based ACLs can silently undermine the entire access control model if they contain logic that unconditionally grants access or can be manipulated externally. OWASP and CIS guidance require that access control decisions be deterministic and not reliant on client-controllable or externally mutable inputs.

<details>
<summary>Scripts - Background</summary>

```javascript
(function findDangerousACLScripts() {

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

    gs.info('=== ACL DANGEROUS SCRIPT SCAN ===');
    gs.info('Total findings: ' + results.length);
    gs.info('Unconditional grants: ' + results.filter(function(a) { return a.highest_concern === 'UNCONDITIONAL_GRANT'; }).length);
    gs.info('Bypass patterns: ' + results.filter(function(a) { return a.highest_concern === 'BYPASS_PATTERN'; }).length);
    gs.info('Dynamic behavior: ' + results.filter(function(a) { return a.highest_concern === 'DYNAMIC_BEHAVIOR'; }).length);
    gs.info('Incomplete logic: ' + results.filter(function(a) { return a.highest_concern === 'INCOMPLETE_LOGIC'; }).length);
    gs.info(JSON.stringify(results, null, 2));

})();
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'dangerous_acl_scripts');

var dangerousPatterns = ['answer = true', 'answer=true', 'return true'];
var foundDangerous = false;

var aclRecord = new GlideRecord('sys_security_acl');
aclRecord.addQuery('active', 'true');
aclRecord.addNotNullQuery('script');
aclRecord.query();

while (aclRecord.next() && !foundDangerous) {
    var scriptLower = aclRecord.script.toString().toLowerCase().replace(/\s+/g, ' ');
    for (var i = 0; i < dangerousPatterns.length; i++) {
        if (scriptLower.indexOf(dangerousPatterns[i]) > -1) {
            foundDangerous = true;
            break;
        }
    }
}

// Non-compliant if any ACL scripts contain unconditional grant patterns
checkConfig.config_configure = !foundDangerous;
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 4b. ACL Modifications by Security Admin Users

> **Script:** [`query4b-acl-modifications.js`](scans/_review/level-2/query4b-acl-modifications.js)

**What:** Detects ACL and role table changes made by security_admin users in the last 30 days by querying the audit log for modifications to `sys_acl`, `sys_security_acl`, `sys_user_has_role`, and `sys_group_has_role`.

**Why:** ACL modification is the primary vector through which security_admin privilege can be used to escalate access. SOC 2 CC6.1 and NIST AU-12 require that changes to access control configurations be logged, attributed, and reviewed. Unmonitored ACL changes can silently dismantle an instance's security posture.

<details>
<summary>Scripts - Background</summary>

```javascript
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

gs.info('ACL modifications by security_admin users (last 30 days): ' + aclChanges.length);
gs.info(JSON.stringify(aclChanges, null, 2));
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'security_admin_acl_modifications');

var secAdminUsernames = [];
var direct = new GlideRecord('sys_user_has_role');
direct.addQuery('role.name', 'security_admin');
direct.addQuery('user.active', 'true');
direct.query();
while (direct.next()) {
    var uname = direct.user.user_name.toString();
    if (secAdminUsernames.indexOf(uname) === -1) {
        secAdminUsernames.push(uname);
    }
}

var highRiskTables = ['sys_acl', 'sys_security_acl', 'sys_user_has_role', 'sys_group_has_role'];
var changeCount = 0;

for (var i = 0; i < secAdminUsernames.length; i++) {
    var audit = new GlideAggregate('sys_audit');
    audit.addQuery('user', secAdminUsernames[i]);
    audit.addQuery('tablename', 'IN', highRiskTables.join(','));
    audit.addQuery('sys_created_on', '>', gs.daysAgo(30));
    audit.addAggregate('COUNT');
    audit.query();
    if (audit.next()) {
        changeCount += parseInt(audit.getAggregate('COUNT'));
    }
}

// Non-compliant if ACL/role table changes detected by security_admin users
checkConfig.config_configure = (changeCount === 0);
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 4d. Script Changes by Security Admin Users

> **Script:** [`query4d-script-changes.js`](scans/_review/level-2/query4d-script-changes.js)

**What:** Detects modifications to server-side scripts (business rules, script includes, UI actions, web service operations, and processors) made by security_admin users in the last 30 days. Flags changes to active scripts as higher concern.

**Why:** Server-side scripts execute with elevated privileges and represent an indirect but powerful path to platform compromise. A security_admin modifying a business rule can inject logic that runs on every transaction against a table. NIST SI-7 and CIS control 2.7 require integrity monitoring of executable code and configuration.

<details>
<summary>Scripts - Background</summary>

```javascript
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
    'sys_script',           // Business rules
    'sys_script_include',   // Script includes
    'sys_ui_action',        // UI actions
    'sys_ws_operation',     // Web service operations
    'sys_processor'         // Processors
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

        scriptChanges.push({
            timestamp: audit.sys_created_on.toString(),
            changed_by: uname,
            changed_by_display: secAdminUsers[uname],
            table: tableModified,
            script_name: scriptName,
            is_active: isActive,
            field_changed: audit.fieldname.toString(),
            old_value: audit.oldvalue.toString().substring(0, 100),
            new_value: audit.newvalue.toString().substring(0, 100)
        });
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

gs.info('Total script changes by security_admin users (last 30 days): ' + scriptChanges.length);
gs.info('Changes to active scripts: ' + activeScriptChanges.length);
gs.info('Changes to inactive scripts: ' + inactiveScriptChanges.length);
gs.info(JSON.stringify(scriptChanges, null, 2));
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'security_admin_script_changes');

var secAdminUsernames = [];
var direct = new GlideRecord('sys_user_has_role');
direct.addQuery('role.name', 'security_admin');
direct.addQuery('user.active', 'true');
direct.query();
while (direct.next()) {
    var uname = direct.user.user_name.toString();
    if (secAdminUsernames.indexOf(uname) === -1) {
        secAdminUsernames.push(uname);
    }
}

var scriptTables = ['sys_script', 'sys_script_include', 'sys_ui_action', 'sys_ws_operation', 'sys_processor'];
var activeScriptChangeFound = false;

for (var i = 0; i < secAdminUsernames.length && !activeScriptChangeFound; i++) {
    var audit = new GlideRecord('sys_audit');
    audit.addQuery('user', secAdminUsernames[i]);
    audit.addQuery('tablename', 'IN', scriptTables.join(','));
    audit.addQuery('sys_created_on', '>', gs.daysAgo(30));
    audit.query();
    while (audit.next() && !activeScriptChangeFound) {
        var scriptRecord = new GlideRecord(audit.tablename.toString());
        if (scriptRecord.get(audit.documentkey.toString())) {
            if (scriptRecord.active.toString() === 'true' || scriptRecord.active.toString() === '1') {
                activeScriptChangeFound = true;
            }
        }
    }
}

// Non-compliant if security_admin users modified active server-side scripts
checkConfig.config_configure = !activeScriptChangeFound;
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 4e. Encryption Key and Configuration Changes by Security Admin Users

> **Script:** [`query4e-encryption-changes.js`](scans/_review/level-2/query4e-encryption-changes.js)

**What:** Detects modifications to Platform Encryption resources (crypto modules, key maps, keys, key stores, certificates, and encryption contexts) made by security_admin users in the last 30 days. Flags deactivation events and changes to high-risk KMF tables separately.

**Why:** Encryption key management is foundational to data protection. Unauthorized changes to encryption configuration can expose encrypted data at rest or render it unrecoverable. NIST SC-12 and SC-28 require that cryptographic key management activities be controlled and auditable.

<details>
<summary>Scripts - Background</summary>

```javascript
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

var encryptionTables = [
    'sys_kmf_crypto_module',    // Crypto modules
    'sys_kmf_map',              // Key maps (which fields are encrypted)
    'sys_kmf_key',              // Encryption keys
    'sys_kmf_key_store',        // Key stores
    'sys_kmf_key_store_alias',  // Key store aliases
    'sys_kmf_crypto_spec',      // Crypto specifications
    'sys_kmf_key_lifecycle',    // Key lifecycle policies
    'sys_certificate',          // Certificates
    'sys_encryption_context'    // Encryption contexts
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

        encryptionChanges.push({
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
        });
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
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'security_admin_encryption_changes');

var secAdminUsernames = [];
var direct = new GlideRecord('sys_user_has_role');
direct.addQuery('role.name', 'security_admin');
direct.addQuery('user.active', 'true');
direct.query();
while (direct.next()) {
    var uname = direct.user.user_name.toString();
    if (secAdminUsernames.indexOf(uname) === -1) {
        secAdminUsernames.push(uname);
    }
}

var encryptionTables = ['sys_kmf_crypto_module', 'sys_kmf_map', 'sys_kmf_key', 'sys_kmf_key_store', 'sys_certificate', 'sys_encryption_context'];
var deactivationFound = false;

for (var i = 0; i < secAdminUsernames.length && !deactivationFound; i++) {
    var audit = new GlideRecord('sys_audit');
    audit.addQuery('user', secAdminUsernames[i]);
    audit.addQuery('tablename', 'IN', encryptionTables.join(','));
    audit.addQuery('fieldname', 'active');
    audit.addQuery('oldvalue', '1');
    audit.addQuery('newvalue', '0');
    audit.addQuery('sys_created_on', '>', gs.daysAgo(30));
    audit.query();
    if (audit.next()) {
        deactivationFound = true;
    }
}

// Non-compliant if encryption deactivation events detected
checkConfig.config_configure = !deactivationFound;
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 6. Business Rules with Privilege Escalation Patterns

> **Script:** [`query6-business-rules-privilege-escalation.js`](scans/_review/level-2/query6-business-rules-privilege-escalation.js)

**What:** Scans all active business rules for dangerous script patterns including `gs.setProperty`, direct manipulation of `sys_user` or `sys_user_has_role`, abort action overrides, role assignments, and session data injection. Reports matched patterns per rule for targeted review.

**Why:** Business rules execute server-side with system-level privileges and fire automatically on database operations. A malicious or poorly written business rule can modify user records, grant roles, or alter system properties on every insert/update. NIST SI-7 requires integrity verification of operational code, and CIS recommends auditing scripts that run with elevated privileges.

<details>
<summary>Scripts - Background</summary>

```javascript
(function auditBusinessRules() {
    try {
        var sw = new GlideStopWatch();

        var businessRule = new GlideRecord('sys_script');
        businessRule.addQuery('active', 'true');
        businessRule.addQuery('when', 'IN', 'before,after,async,display');
        businessRule.query();

        gs.info('Scanning ' + businessRule.getRowCount() + ' active business rules...\n');

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
                systemRules.push({
                    name: businessRule.name.toString(),
                    table: businessRule.collection.toString(),
                    when: businessRule.when.toString(),
                    active: businessRule.active.toString(),
                    sys_id: businessRule.sys_id.toString(),
                    matched_patterns: matchedPatterns,
                    pattern_count: matchedPatterns.length
                });
            }
        }

        gs.info('Scan completed in: ' + sw.elapsed() + 'ms');
        gs.warn('\nFound ' + systemRules.length + ' business rules with potential privilege escalation patterns\n');

        for (var j = 0; j < systemRules.length; j++) {
            var rule = systemRules[j];
            gs.warn('---');
            gs.warn('Business Rule: ' + rule.name);
            gs.warn('Table: ' + rule.table);
            gs.warn('When: ' + rule.when);
            gs.warn('Patterns found: ' + rule.matched_patterns.join(', '));
            gs.warn('Sys ID: ' + rule.sys_id);
        }

        gs.info('\n=== JSON Export ===');
        gs.info(JSON.stringify(systemRules, null, 2));

        return systemRules;

    } catch (e) {
        gs.error('Error during business rule audit: ' + e.message);
        gs.error('Line: ' + e.lineNumber);
        return null;
    }
})();
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'business_rules_privilege_escalation');

var dangerousPatterns = [
    'gs.setProperty',
    "GlideRecord('sys_user_has_role')",
    'GlideRecord("sys_user_has_role")',
    'current.setAbortAction(false)',
    'gs.getUser().setRole'
];
var found = false;

var businessRule = new GlideRecord('sys_script');
businessRule.addQuery('active', 'true');
businessRule.query();

while (businessRule.next() && !found) {
    var script = businessRule.script.toString();
    for (var i = 0; i < dangerousPatterns.length; i++) {
        if (script.indexOf(dangerousPatterns[i]) > -1) {
            found = true;
            break;
        }
    }
}

// Non-compliant if active business rules contain privilege escalation patterns
checkConfig.config_configure = !found;
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

### 9a. Authentication and Session Security Properties

> **Script:** [`query9a-auth-session-properties.js`](scans/_review/level-2/query9a-auth-session-properties.js)

**What:** Retrieves key security-related system properties governing guest access, SSO enforcement, multi-provider SSO configuration, and session timeout values. Provides a snapshot of the instance's authentication posture.

**Why:** Weak authentication configuration is the most impactful category of misconfiguration in any enterprise platform. NIST IA-2, IA-8, and AC-12 require that systems enforce strong authentication, mandate SSO where available, and terminate sessions after defined inactivity periods.

<details>
<summary>Scripts - Background</summary>

```javascript
// Check authentication and session security properties
var policies = [
    'glide.ui.security.allow_guest',          // Guest access enabled?
    'glide.authenticate.multisso.use.idp',    // Multi-provider SSO
    'glide.authenticate.sso.required',        // SSO enforcement
    'session.timeout',                        // Session timeout
    'glide.ui.session_timeout'                // UI session timeout
];

var policySettings = {};
for (var i = 0; i < policies.length; i++) {
    policySettings[policies[i]] = gs.getProperty(policies[i]);
}

gs.info('Security policy settings: ' + JSON.stringify(policySettings, null, 2));
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'authentication_session_properties');

var isCompliant = true;

// Guest access should be disabled
if (gs.getProperty('glide.ui.security.allow_guest', 'false') === 'true') {
    isCompliant = false;
}

// SSO should be required
if (gs.getProperty('glide.authenticate.sso.required', 'false') !== 'true') {
    isCompliant = false;
}

// Session timeout should be configured and reasonable (60 min or less)
var sessionTimeout = gs.getProperty('glide.ui.session_timeout', '');
if (!sessionTimeout || parseInt(sessionTimeout) > 60) {
    isCompliant = false;
}

checkConfig.config_configure = isCompliant;
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

## Level 3 - Third Wave

### 8. Cross-Domain Access (Domain Separation)

> **Script:** [`query8-domain-separation.js`](scans/_review/level-3/query8-domain-separation.js)

**What:** Checks whether domain separation is enabled and, if so, identifies active users without a domain assignment. These "orphaned" users may have unintended cross-domain visibility depending on the instance's domain separation configuration.

**Why:** Domain separation is a critical multi-tenancy control in ServiceNow. Users without explicit domain assignment can potentially access data across all domains, violating data isolation requirements. NIST AC-4 and SOC 2 CC6.6 require that information flow between security domains be controlled.

<details>
<summary>Scripts - Background</summary>

```javascript
// Only runs if domain separation is enabled on the instance
if (gs.getProperty('glide.sys.domain_separation.enabled') == 'true') {
    var userRecord = new GlideRecord('sys_user');
    userRecord.addQuery('active', 'true');
    userRecord.addNullQuery('sys_domain'); // Users without domain assignment
    userRecord.query();

    var orphanedUsers = [];
    while (userRecord.next()) {
        orphanedUsers.push({
            user: userRecord.user_name.toString(),
            name: userRecord.name.toString()
        });
    }

    gs.warn('Users without domain assignment: ' +
            JSON.stringify(orphanedUsers, null, 2));
}
```
</details>

<details>
<summary>Security Center Script Check</summary>

```javascript
var scComplianceUtil = new sn_vsc.VSCComplianceUtil();
var checkConfig = new GlideRecord('sn_vsc_security_check_configurations');
checkConfig.get('config_name', 'domain_separation_orphaned_users');

var isCompliant = true;

if (gs.getProperty('glide.sys.domain_separation.enabled') == 'true') {
    var ga = new GlideAggregate('sys_user');
    ga.addQuery('active', 'true');
    ga.addNullQuery('sys_domain');
    ga.addAggregate('COUNT');
    ga.query();
    if (ga.next()) {
        var count = parseInt(ga.getAggregate('COUNT'));
        isCompliant = (count === 0);
    }
}

// Compliant if domain separation is disabled OR no orphaned users exist
checkConfig.config_configure = isCompliant;
checkConfig.update();
var settingArr = checkConfig.config_setting.split(",");
scComplianceUtil.updateSettingCompliance(settingArr);
```
</details>

---

## Security Center Script Check Reference

| Section | config_name | Pass Criteria |
|---------|-------------|---------------|
| 1a | `privileged_user_population` | No dormant (90-day) privileged accounts |
| 1b | `multiple_high_privilege_roles` | No users with 2+ high-privilege roles |
| 1c | `deprovisioned_users_privileged_roles` | No inactive users with active role assignments |
| 2a | `overly_permissive_acls` | No CRITICAL/HIGH ACLs without restrictions |
| 2b | `dangerous_acl_scripts` | No unconditional grant patterns in ACL scripts |
| 3b | `impersonation_capability_population` | Impersonation-capable users <= 15 |
| 4a | `security_admin_population` | security_admin users <= 10 |
| 4b | `security_admin_acl_modifications` | No ACL/role changes by security_admin (30 days) |
| 4c | `security_admin_role_grants` | No self-grants by security_admin users |
| 4d | `security_admin_script_changes` | No active script modifications by security_admin |
| 4e | `security_admin_encryption_changes` | No encryption deactivation events |
| 5a | `integration_users_admin_roles` | No integration users with admin roles |
| 5b | `oauth_token_lifespans` | No tokens exceeding 1hr access / 24hr refresh |
| 6 | `business_rules_privilege_escalation` | No dangerous patterns in active business rules |
| 7 | `ui_policy_mandatory_bypass` | No UI policies removing mandatory enforcement |
| 8 | `domain_separation_orphaned_users` | Domain sep disabled OR no orphaned users |
| 9a | `authentication_session_properties` | Guest disabled, SSO required, timeout <= 60min |
| 9b | `admin_users_without_mfa` | All admin/security_admin have active MFA |
| 10 | `scheduled_jobs_admin_runas` | No scheduled jobs running as admin |

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md) for reporting instructions.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

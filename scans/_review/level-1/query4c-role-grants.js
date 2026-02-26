/**
 * Query 4-3: Role Grants Made by security_admin Users
 *
 * Purpose:
 * Detects role assignment changes made by users with the security_admin role.
 * Role grants are the most direct indicator of privilege escalation activity.
 *
 * What it checks:
 * - Builds the security_admin population from direct and group-inherited assignments
 * - Queries sys_audit for changes against sys_user_has_role and sys_group_has_role
 *   by that population
 * - Flags self-grants and grants of admin, security_admin, or impersonator
 * - Lookback window is configurable (default 30 days)
 *
 * Known false positive patterns:
 * Role grants during clone operations or upgrades may appear as the clone
 * process restores role assignments. Correlate timestamps against clone and
 * upgrade history before escalating.
 *
 * Tables queried: sys_user_has_role, sys_group_has_role, sys_user_grmember,
 * sys_audit
 */

var secAdminUsers = {};

function collectUser(userSysId) {
    if (!userSysId) return;
    var u = new GlideRecord('sys_user');
    if (u.get(userSysId) && u.active) {
        secAdminUsers[u.user_name.toString()] = u.name.toString();
    }
}

var direct = new GlideRecord('sys_user_has_role');
direct.addQuery('role.name', 'security_admin');
direct.addQuery('user.active', 'true');
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
    audit.addQuery('sys_created_on', '>', gs.daysAgo(30));
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
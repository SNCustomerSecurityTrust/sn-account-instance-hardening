/**
 * Query 4-2: ACL Modifications by security_admin Users
 *
 * Purpose:
 * Detects ACL changes made by users with the security_admin role against
 * high-risk tables. ACL modification is a primary vector through which
 * security_admin can be used to escalate privileges.
 *
 * What it checks:
 * - Builds the security_admin population from direct and group-inherited assignments
 * - Queries sys_audit for changes against sys_acl, sys_security_acl,
 *   sys_user_has_role, and sys_group_has_role by that population
 * - Captures what changed, when, and by whom
 * - Lookback window is configurable (default 30 days)
 *
 * Known false positive patterns:
 * Clone-related ACLs (clone_data_exclude, clone_data_preserver,
 * clone_cleanup_script, clone_profile_exclusions, clone_profile_preservers,
 * clone_profile_cleanup_scripts) are routinely deactivated during instance
 * clones. Correlate timestamps against clone history before escalating.
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

var highRiskTables = ['sys_acl', 'sys_security_acl', 'sys_user_has_role', 'sys_group_has_role'];
var aclChanges = [];

for (var i = 0; i < secAdminUsernames.length; i++) {
    var uname = secAdminUsernames[i];
    var audit = new GlideRecord('sys_audit');
    audit.addQuery('user', uname);
    audit.addQuery('tablename', 'IN', highRiskTables.join(','));
    audit.addQuery('sys_created_on', '>', gs.daysAgo(30));
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
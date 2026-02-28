/**
 * Query 4-4: Business Rule and Script Include Changes by security_admin Users
 *
 * Purpose:
 * Detects modifications to server-side scripts made by users with the
 * security_admin role. Scripts execute with elevated server-side privileges
 * and represent an indirect but powerful path to platform compromise.
 *
 * What it checks:
 * - Builds the security_admin population from direct and group-inherited assignments
 * - Queries sys_audit for changes against sys_script, sys_script_include,
 *   sys_ui_action, sys_ws_operation, and sys_processor by that population
 * - Flags changes to active scripts as higher concern than inactive ones
 * - Truncates old and new values to 100 characters for readability
 * - Lookback window is configurable (default 30 days)
 *
 * Known false positive patterns:
 * Upgrade and patch operations generate bulk script changes simultaneously.
 * Plugin activations may also trigger script record creation. Correlate
 * bulk changes against upgrade or patch history before escalating.
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

var scriptTables = [
    'sys_script',
    'sys_script_include',
    'sys_ui_action',
    'sys_ws_operation',
    'sys_processor'
];

var scriptChanges = [];

for (var i = 0; i < secAdminUsernames.length; i++) {
    var uname = secAdminUsernames[i];
    var audit = new GlideRecord('sys_audit');
    audit.addQuery('user', uname);
    audit.addQuery('tablename', 'IN', scriptTables.join(','));
    audit.addQuery('sys_created_on', '>', gs.daysAgo(30));
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
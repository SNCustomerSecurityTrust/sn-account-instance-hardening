/**
 * Query 4-1: Users with security_admin Role
 *
 * Purpose:
 * Identifies all active users with the security_admin role assigned directly
 * or via group membership. Serves as the population anchor for queries 4-2
 * through 4-5 which detect behavioral indicators of privilege escalation.
 *
 * What it checks:
 * - Direct security_admin role assignments
 * - Group-inherited security_admin assignments
 * - Whether the user also holds admin (compounding privilege)
 * - Last login timestamp and service account flag
 *
 * Tables queried: sys_user_has_role, sys_group_has_role, sys_user_grmember
 */

var secAdmins = {};

function addUser(userSysId, source) {
    if (!userSysId) return;
    var u = new GlideRecord('sys_user');
    if (u.get(userSysId)) {
        if (!u.active) return;
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
    var adminCheck = new GlideRecord('sys_user_has_role');
    adminCheck.addQuery('user.user_name', uname);
    adminCheck.addQuery('role.name', 'admin');
    adminCheck.addQuery('user.active', 'true');
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
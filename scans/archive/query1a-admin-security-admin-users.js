/**
 * Query 1a: Users with Admin or Security Admin Roles
 *
 * Purpose:
 * Identifies all active users with high privilege roles directly assigned,
 * specifically admin, security_admin, and user_admin. These roles represent
 * the broadest access levels on a ServiceNow instance and should be assigned
 * only to a minimal number of named individuals with a documented business need.
 *
 * What it checks:
 * - Direct role assignments for admin, security_admin, and user_admin
 * - Group-inherited assignments for the same roles
 * - Last login timestamp to identify dormant privileged accounts
 * - Whether the user holds multiple high privilege roles
 * - Potential service account flag based on username convention
 *
 * Tables queried: sys_user_has_role, sys_group_has_role, sys_user_grmember
 */

var privilegedRoles = ['admin', 'security_admin', 'user_admin'];
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
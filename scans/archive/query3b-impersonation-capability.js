/**
 * Query 3-1: Comprehensive Impersonation Capability Assessment
 *
 * Purpose:
 * Identifies all active users who can impersonate other users within the
 * ServiceNow instance, regardless of how that capability was granted.
 *
 * What it checks:
 * Evaluates five vectors through which impersonation capability may be granted:
 *   1. Direct assignment of the impersonator role
 *   2. Direct assignment of the admin role
 *   3. Direct assignment of security_admin
 *   4. Group membership where the group holds impersonator, admin, or security_admin
 *   5. Role hierarchy where a parent role contains impersonator as a child role
 * Results are deduplicated with a sources array showing every vector per user.
 *
 * Tables queried: sys_user_has_role, sys_group_has_role, sys_user_grmember,
 * sys_user_role_contains
 */

var impersonators = {};

function addUser(userSysId, source) {
    if (!userSysId) return;
    var u = new GlideRecord('sys_user');
    if (u.get(userSysId)) {
        if (!u.active) return;
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
direct.query();
while (direct.next()) {
    addUser(direct.getValue('user'), 'direct:impersonator');
}

// 2. Direct admin role
var adminDirect = new GlideRecord('sys_user_has_role');
adminDirect.addQuery('role.name', 'admin');
adminDirect.addQuery('user.active', 'true');
adminDirect.query();
while (adminDirect.next()) {
    addUser(adminDirect.getValue('user'), 'direct:admin');
}

// 3. Direct security_admin role
var secAdmin = new GlideRecord('sys_user_has_role');
secAdmin.addQuery('role.name', 'security_admin');
secAdmin.addQuery('user.active', 'true');
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

// 5. Parent roles containing impersonator as a child role
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
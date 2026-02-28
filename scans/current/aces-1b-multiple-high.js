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
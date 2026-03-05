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
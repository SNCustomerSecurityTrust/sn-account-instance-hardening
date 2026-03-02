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

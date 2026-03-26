(function(engine) {

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

		//var userRec = inactiveRoles.user.getRefRecord();
		//engine.finding.setCurrentSource(userRec);
		//engine.finding.increment();

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

    // Flag recently deactivated users (last 60 days) - highest reactivation risk
    // Note: uses sys_updated_on as proxy since ServiceNow has no dedicated deactivation timestamp
    var recentlyDeactivated = [];
    var allRecords = direct.concat(inherited);

    for (var i = 0; i < allRecords.length; i++) {
        var deactivatedUser = new GlideRecord('sys_user');
        deactivatedUser.get(allRecords[i].user_sys_id);
        var updatedOn = new GlideDateTime(deactivatedUser.sys_updated_on.toString());
        var checkDaysAgo = new GlideDateTime();
        checkDaysAgo.addDaysUTC(-60);
        if (updatedOn.compareTo(checkDaysAgo) < 0) {
			
			engine.finding.setCurrentSource(deactivatedUser);
			engine.finding.setValue('finding_details','Inactive account w high-perm roles (older than 60 days)');
			engine.finding.increment();

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

    var serviceAccounts = allRecords.filter(function(u) {
        return u.is_service_account;
    });

    // gs.info('=== DEPROVISIONED USERS WITH PRIVILEGED ROLES ===');
    // gs.info('Direct assignments (critical - survives reactivation): ' + direct.length);
    // gs.info('Inherited assignments (high - survives reactivation): ' + inherited.length);
    // gs.info('Total records: ' + (direct.length + inherited.length));
    // gs.info('Recently deactivated (<90 days, highest reactivation risk): ' + recentlyDeactivated.length);
    // gs.info('Potential service accounts: ' + serviceAccounts.length);
    // gs.info('\nDirect assignments:');
    // gs.info(JSON.stringify(direct, null, 2));
    // gs.info('\nInherited assignments:');
    // gs.info(JSON.stringify(inherited, null, 2));
    // gs.info('\nRecently deactivated users:');
    // gs.info(JSON.stringify(recentlyDeactivated, null, 2));

})(engine);

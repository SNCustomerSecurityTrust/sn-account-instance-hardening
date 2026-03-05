(function (engine) {
	// Find privileged users without MFA enrolled
	var privilegedUserIds = {};
	var adminRoleQuery = new GlideRecord('sys_user_has_role');
	adminRoleQuery.addQuery('role.name', 'IN', 'admin,security_admin');
	adminRoleQuery.addQuery('user.active', 'true');
	adminRoleQuery.addQuery('state', 'active');
	adminRoleQuery.query();
	while (adminRoleQuery.next()) {
		privilegedUserIds[adminRoleQuery.getValue('user')] = true;
	}
	var noMFAUsers = [];
	for (var userId in privilegedUserIds) {
		var userRecord = new GlideRecord('sys_user');
		if (userRecord.get(userId)) {
			var mfaDevice = new GlideRecord('sys_user_multi_factor_setup');
			mfaDevice.addQuery('user', userId);
			mfaDevice.addQuery('active', 'true');
			mfaDevice.query();
			if (!mfaDevice.hasNext()) {
				engine.finding.setCurrentSource(userRecord);
				//engine.finding.setValue('finding_details','Found with DIRECT role assignment');
				engine.finding.increment();

				noMFAUsers.push({
					user: userRecord.user_name.toString(),
					name: userRecord.name.toString(),
					email: userRecord.email.toString()
				});
			}
		}
	}
	//gs.warn('Admin users without MFA: ' + JSON.stringify(noMFAUsers, null, 2));
})(engine);
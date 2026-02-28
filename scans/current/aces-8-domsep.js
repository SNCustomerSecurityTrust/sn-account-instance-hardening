(function(engine) {

    // Only runs if domain separation is enabled on the instance

	var userRecord = new GlideRecord('sys_user');
	userRecord.addQuery('active', 'true');
	userRecord.addNullQuery('sys_domain'); // Users without domain assignment
	userRecord.query();

	var orphanedUsers = [];
	while (userRecord.next()) {

		engine.finding.setCurrentSource(userRecord);
		engine.finding.setValue('finding_details','User is active and has no domain assignment.');
		engine.finding.increment();

		orphanedUsers.push({
			user: userRecord.user_name.toString(),
			name: userRecord.name.toString()
		});
	}

	//gs.warn('Users without domain assignment: ' + JSON.stringify(orphanedUsers, null, 2));
   

})(engine);
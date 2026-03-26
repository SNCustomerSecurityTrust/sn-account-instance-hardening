(function(engine) {

    // Find scheduled jobs configured to run as admin users
    var scheduledJob = new GlideRecord('sysauto_script');
    scheduledJob.addQuery('active', 'true');
    scheduledJob.query();

    var adminJobs = [];
    while (scheduledJob.next()) {
        var runAs = scheduledJob.run_as.toString();
        var runAsUser = new GlideRecord('sys_user');

        if (runAs && runAsUser.get(runAs)) {
            var adminRoleCheck = new GlideRecord('sys_user_has_role');
            adminRoleCheck.addQuery('user', runAs);
            adminRoleCheck.addQuery('role.name', 'admin');
            adminRoleCheck.addQuery('state', 'active');
            adminRoleCheck.query();
            if (adminRoleCheck.hasNext()) {

                engine.finding.setCurrentSource(scheduledJob);
				engine.finding.setValue('finding_details', scheduledJob.sys_name.getDisplayValue() + ' running as user:'+runAsUser.getDisplayValue());
                engine.finding.increment();

                adminJobs.push({
                    name: scheduledJob.name.toString(),
                    run_as: runAsUser.name.toString(),
                    run_dayofweek: scheduledJob.run_dayofweek.toString(),
                    run_time: scheduledJob.run_time.toString()
                });
            }
        }
    }

    //gs.info('Scheduled jobs running as admin: ' + JSON.stringify(adminJobs, null, 2));

})(engine);

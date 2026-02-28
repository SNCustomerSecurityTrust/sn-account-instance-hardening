// Find scheduled jobs with elevated privileges

var gr = new GlideRecord('sysauto_script');
gr.addQuery('active', 'true');
gr.query();

var adminJobs = [];
while (gr.next()) {
    var runAs = gr.run_as.toString();
    var runAsUser = new GlideRecord('sys_user');
    
    if (runAs && runAsUser.get(runAs)) {
        if (runAsUser.hasRole('admin')) {
            adminJobs.push({
                name: gr.name.toString(),
                run_as: runAsUser.name.toString(),
                run_dayofweek: gr.run_dayofweek.toString(),
                run_time: gr.run_time.toString()
            });
        }
    }
}

gs.info('Scheduled jobs running as admin: ' + JSON.stringify(adminJobs, null, 2));


//.hasRole('admin') is not a valid function
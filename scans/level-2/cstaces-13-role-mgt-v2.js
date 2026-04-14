(function(engine) {

    if (!GlidePluginManager.isRegistered('com.glide.role_management.inh_count')) {

        //engine.finding.setCurrentSource(scheduledJob);
        engine.finding.setValue('finding_details', 'Risk Management v2 plugin is not installed. Consider installing.');
        engine.finding.increment();

    }


})(engine);

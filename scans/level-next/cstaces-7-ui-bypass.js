(function (engine) {
	var uiPolicy = new GlideRecord('sys_ui_policy');
	uiPolicy.addQuery('active', 'true');
	uiPolicy.query();
	while (uiPolicy.next()) {
		var actions = new GlideRecord('sys_ui_policy_action');
		actions.addQuery('ui_policy', uiPolicy.getUniqueValue());
		actions.addQuery('mandatory', 'false');
		actions.query();
		if (actions.hasNext()) {
			gs.info('UI Policy bypassing mandatory fields: ' + uiPolicy.short_description.toString());
			engine.finding.setCurrentSource(actions);
			engine.finding.setValue('finding_details','Possible finding. Needs review.');
			engine.finding.increment();
		}
	}
})(engine);
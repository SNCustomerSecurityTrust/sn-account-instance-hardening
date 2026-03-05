(function (engine) {
	// Check authentication and session security properties
	var policies = [
		'glide.ui.security.allow_guest',          // Guest access enabled?
		'glide.authenticate.multisso.use.idp',    // Multi-provider SSO
		'glide.authenticate.sso.required',        // SSO enforcement
		'glide.ui.session_timeout'                // UI session timeout
	];
		//'session.timeout',                        // Session timeout

	var policySettings = {};
	for (var i = 0; i < policies.length; i++) {
		
		//Get Value - Traditional Method
		
		var policyValue = gs.getProperty(policies[i]);
		policySettings[policies[i]] = policyValue;
		//Get Record
		var propRec = new GlideRecord('sys_properties');
		propRec.addQuery('name',policies[i]);
		propRec.query();
		if(propRec.next()){
			engine.finding.setCurrentSource(propRec);
			engine.finding.setValue('finding_details','Property currently configured as:'+policyValue);
			engine.finding.increment();
		}else{
			gs.warn('Instance Scan Check cant find prop:'+policies[i]);
		}

	}
	//gs.info('Security policy settings: ' + JSON.stringify(policySettings, null, 2));
})(engine);
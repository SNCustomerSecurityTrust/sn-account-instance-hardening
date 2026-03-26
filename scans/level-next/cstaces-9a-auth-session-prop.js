(function (engine) {

	// Check authentication and session security properties
	var policies = [
		'glide.authenticate.sso.redirect.idp',
		'glide.authenticate.multisso.enabled',
		'glide.authenticate.sso.required',        // SSO enforcement
		'glide.ui.session_timeout'                // UI session timeout
	];
		//'session.timeout',                        // Session timeout
		//'glide.ui.security.allow_guest',          // Guest access enabled?
		//'glide.authenticate.multisso.use.idp',    // Multi-provider SSO

	var policySettings = {};
	for (var i = 0; i < policies.length; i++) {
		
		//Get Value - Traditional Method
		
		var policyValue = gs.getProperty(policies[i]);
		policySettings[policies[i]] = policyValue;


		//engine.finding.setCurrentSource(propRec);
		engine.finding.setValue('finding_details','1Property currently configured as:'+policyValue);
		engine.finding.increment();

		//Get Record
		var propRec = new GlideRecord('sys_properties');
		propRec.addQuery('name',policies[i]);
		propRec.query();
		if(propRec.next()){

			engine.finding.setCurrentSource(propRec);
			engine.finding.setValue('finding_details','2Property currently configured as:'+policyValue);
			engine.finding.increment();

		}else{

			engine.finding.setValue('finding_details','Cant find prop:'+policies[i]);
			engine.finding.increment();

		}



	}

	//gs.info('Security policy settings: ' + JSON.stringify(policySettings, null, 2));

})(engine);

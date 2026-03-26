(function(engine) {

    // Audit active OAuth applications and their token lifespans
    var oauthEntity = new GlideRecord('oauth_entity');
    oauthEntity.addQuery('active', 'true');
    oauthEntity.query();

    var oauthApps = [];
    while (oauthEntity.next()) {


		//Get extended record
		var oauthRec = new GlideRecord(oauthEntity.sys_class_name);
		oauthRec.get(oauthEntity.getUniqueValue());

		var oauthName = oauthRec.name.getDisplayValue();

		var oauthTypeDisp = oauthRec.type.getDisplayValue();
		var oauthTypeStr = oauthRec.type.getValue();

		var oauthGrantDisp = oauthRec.default_grant_type.getDisplayValue();
		var oauthGrantStr = oauthRec.default_grant_type.getValue();


		var findingStr = oauthName + ' ('+ oauthGrantDisp + ') - Review and disable record or mute finding.';

		engine.finding.setCurrentSource(oauthEntity);
		engine.finding.setValue('finding_details',findingStr);
		engine.finding.increment();


        // oauthApps.push({
        //     name: oauthEntity.name.toString(),
        //     client_id: oauthEntity.client_id.toString(),
        //     redirect_url: oauthEntity.redirect_url.toString(),
        //     access_token_lifespan: oauthEntity.access_token_lifespan.toString(),
        //     refresh_token_lifespan: oauthEntity.refresh_token_lifespan.toString()
        // });
    }

    //gs.info('Active OAuth applications: ' + JSON.stringify(oauthApps, null, 2));

})(engine);

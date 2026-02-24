
//Q5b Active OAuth clients/ scopes 
//*Remediation: Access/ Refresh Token Expiry 

// Audit OAuth applications and their scopes
var gr = new GlideRecord('oauth_entity');
gr.addQuery('active', 'true');
gr.query();

var oauthApps = [];
while (gr.next()) {
    oauthApps.push({
        name: gr.name.toString(),
        client_id: gr.client_id.toString(),
        redirect_url: gr.redirect_url.toString(),
        access_token_lifespan: gr.access_token_lifespan.toString(),
        refresh_token_lifespan: gr.refresh_token_lifespan.toString()
    });
}

gs.info('Active OAuth applications: ' + JSON.stringify(oauthApps, null, 2));

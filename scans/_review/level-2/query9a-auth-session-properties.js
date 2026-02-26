

//Q9 Modern Authentication Discovery/ Remediation (SAML/ OIDC/ MFA)
// Check password policy settings
var policies = [
    'glide.ui.security.allow_guest',
    'glide.authenticate.multisso.use.idp',
    'glide.authenticate.sso.required',
    'session.timeout',
    'glide.ui.session_timeout' //Found SC Check
];

var policySettings = {};
policies.forEach(function(policy) {
    policySettings[policy] = gs.getProperty(policy);
});

gs.info('Security policy settings: ' + JSON.stringify(policySettings, null, 2));


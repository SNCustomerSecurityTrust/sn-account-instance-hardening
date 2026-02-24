/*
For verifying that adaptive auth is "turned on" for 
interactive logins specifically, you need to confirm 
three things: the plugin is active, the master property 
is enabled, and at least one active policy exists 
within a post-authentication context (since interactive 
login policies execute post-auth).
*/

(function verifyAdaptiveAuth() {
    var results = {
        pluginActive: false,
        propertyEnabled: false,
        activePolicies: 0,
        contexts: []
    };

    // 1. Check if the Adaptive Authentication plugin is active
    results.pluginActive = GlidePluginManager.isActive('com.snc.adaptive_authentication');

    // 2. Check the master switch property
    var propValue = gs.getProperty('glide.authenticate.auth.policy.enabled', 'false');
    results.propertyEnabled = (propValue.toLowerCase() === 'true');

    // 3. Query active policy contexts with active policies
    var ctxGR = new GlideRecord('sys_auth_policy_context');
    ctxGR.addQuery('active', true);
    ctxGR.query();

    while (ctxGR.next()) {
        var contextInfo = {
            name: ctxGR.getDisplayValue('name'),
            type: ctxGR.getDisplayValue('type'),
            activePolicies: 0
        };

        // Count active policies under this context
        var polGR = new GlideRecord('sys_auth_policy');
        polGR.addQuery('context', ctxGR.getUniqueValue());
        polGR.addQuery('active', true);
        polGR.query();
        contextInfo.activePolicies = polGR.getRowCount();
        results.activePolicies += contextInfo.activePolicies;

        results.contexts.push(contextInfo);
    }

    // Report
    gs.info('=== Adaptive Authentication Verification ===');
    gs.info('Plugin Active: ' + results.pluginActive);
    gs.info('Property Enabled (glide.authenticate.auth.policy.enabled): ' + results.propertyEnabled);
    gs.info('Total Active Policies: ' + results.activePolicies);
    gs.info('---');

    for (var i = 0; i < results.contexts.length; i++) {
        var c = results.contexts[i];
        gs.info('Context: ' + c.name + ' | Type: ' + c.type + ' | Active Policies: ' + c.activePolicies);
    }

    // Verdict
    if (!results.pluginActive) {
        gs.warn('FAIL: Adaptive Authentication plugin is NOT active.');
    } else if (!results.propertyEnabled) {
        gs.warn('FAIL: Plugin is active but the master property is DISABLED. Policies will NOT execute.');
    } else if (results.activePolicies === 0) {
        gs.warn('FAIL: Plugin and property are enabled but NO active policies exist.');
    } else {
        gs.info('PASS: Adaptive Authentication is active with ' + results.activePolicies + ' active policy(ies).');
    }

})();
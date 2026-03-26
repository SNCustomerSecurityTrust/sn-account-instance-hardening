/**
 * Instance Scan Check: glide.knowman.block_access_with_no_user_criteria
 * Check ID: cstaces-11a
 *
 * Type:     Script Only
 * Category: KB Security — System Properties
 * Severity: Critical
 *
 * Checks that glide.knowman.block_access_with_no_user_criteria is set to 'true'.
 * When false (default on pre-Orlando instances), any KB without explicit
 * user criteria is accessible to ALL users — including unauthenticated/guest.
 *
 * This is the #1 root cause of KB data exposures per AppOmni's 2024 research
 * (45% of tested enterprise instances were leaking KB data).
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    var PROP_NAME = 'glide.knowman.block_access_with_no_user_criteria';
    var finding = false;
    var detail = '';

    var propRec = new GlideRecord('sys_properties');
    propRec.addQuery('name', PROP_NAME);
    propRec.query();

    if (propRec.next()) {
        if (propRec.getValue('value') !== 'true') {
            finding = true;
            detail = 'Property "' + PROP_NAME + '" is set to "' + propRec.getValue('value') +
                '". This means knowledge bases without user criteria are accessible to ALL users, ' +
                'including unauthenticated guests. Set this property to "true" immediately.';
        }
    } else {
        // Property does not exist — treat as false (the insecure default)
        finding = true;
        detail = 'Property "' + PROP_NAME + '" does not exist on this instance. ' +
            'The default behavior is to allow access to KBs with no user criteria. ' +
            'Create this property and set it to "true".';
    }

    if (finding) {
        engine.finding.setCurrentSource(propRec);
        engine.finding.setValue('finding_details', detail);
        engine.finding.increment();
    }

})(engine);

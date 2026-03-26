/**
 * Instance Scan Check: glide.knowman.show_unpublished
 * Check ID: cstaces-11d
 *
 * Type:     Script Only
 * Category: KB Security — System Properties
 * Severity: High
 *
 * Checks that glide.knowman.show_unpublished is NOT set to 'true'.
 * When true, articles in Draft, Review, or other non-Published workflow states
 * are visible in the Knowledge portal and search results.
 *
 * Unpublished articles may contain sensitive, unreviewed content.
 */

(function(engine) {

    var PROP_NAME = 'glide.knowman.show_unpublished';

    var propRec = new GlideRecord('sys_properties');
    propRec.addQuery('name', PROP_NAME);
    propRec.query();

    if (propRec.next()) {
        if (propRec.getValue('value') === 'true') {
            engine.finding.setCurrentSource(propRec);
            engine.finding.setValue('finding_details',
                'Property "' + PROP_NAME + '" is set to "true". ' +
                'Draft, review, and other non-published articles are visible in the Knowledge portal ' +
                'and search results. This bypasses the editorial/approval workflow and may leak ' +
                'sensitive content before it has been reviewed. Set to "false".');
            engine.finding.increment();
        }
    }
    // If property does not exist, default is false (secure) — no finding

})(engine);

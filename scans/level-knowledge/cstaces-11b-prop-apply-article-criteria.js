/**
 * Instance Scan Check: glide.knowman.apply_article_read_criteria
 * Check ID: cstaces-11b
 *
 * Type:     Script Only
 * Category: KB Security — System Properties
 * Severity: High
 *
 * Checks that glide.knowman.apply_article_read_criteria is set to 'true'.
 * When false (default), users with KB-level "Can Contribute" access bypass
 * ALL article-level "Can Read" and "Cannot Read" user criteria.
 *
 * This defeats article-level access segmentation within a shared KB.
 *
 * Reference: https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0966771
 */

(function(engine) {

    var PROP_NAME = 'glide.knowman.apply_article_read_criteria';
    var finding = false;
    var detail = '';

    var propRec = new GlideRecord('sys_properties');
    propRec.addQuery('name', PROP_NAME);
    propRec.query();

    if (propRec.next()) {
        if (propRec.getValue('value') !== 'true') {
            finding = true;
            detail = 'Property "' + PROP_NAME + '" is set to "' + propRec.getValue('value') +
                '". Contributors to a KB can read ALL articles regardless of article-level ' +
                'user criteria restrictions. Set to "true" if you use article-level access controls.';
        }
    } else {
        finding = true;
        detail = 'Property "' + PROP_NAME + '" does not exist. ' +
            'Default behavior allows KB contributors to bypass article-level read restrictions. ' +
            'Create this property and set it to "true".';
    }

    if (finding) {
        engine.finding.setCurrentSource(propRec);
        engine.finding.setValue('finding_details', detail);
        engine.finding.increment();
    }

})(engine);

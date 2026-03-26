/**
 * Instance Scan Check: glide.knowman.search.apply_role_based_security
 * Check ID: cstaces-11c
 *
 * Type:     Script Only
 * Category: KB Security — System Properties
 * Severity: High
 *
 * Checks that glide.knowman.search.apply_role_based_security is set to 'true'.
 * When false, role-based access checks on the 'roles' field of kb_knowledge
 * articles are bypassed during search, potentially leaking restricted articles
 * in search results.
 *
 * Reference: https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0824545
 */

(function(engine) {

    var PROP_NAME = 'glide.knowman.search.apply_role_based_security';
    var finding = false;
    var detail = '';

    var propRec = new GlideRecord('sys_properties');
    propRec.addQuery('name', PROP_NAME);
    propRec.query();

    if (propRec.next()) {
        if (propRec.getValue('value') !== 'true') {
            finding = true;
            detail = 'Property "' + PROP_NAME + '" is set to "' + propRec.getValue('value') +
                '". Role-based security on KB articles is not enforced during search. ' +
                'Articles with role restrictions may appear in search results for unauthorized users. ' +
                'Set to "true".';
        }
    } else {
        finding = true;
        detail = 'Property "' + PROP_NAME + '" does not exist. ' +
            'This property may need to be manually created on some instances. ' +
            'Without it, role-based article restrictions are not enforced during search.';
    }

    if (finding) {
        engine.finding.setCurrentSource(propRec);
        engine.finding.setValue('finding_details', detail);
        engine.finding.increment();
    }

})(engine);

/**
 * Instance Scan Check: Articles with the 'public' role set
 * Check ID: cstaces-11t
 *
 * Type:     Script Only
 * Category: KB Security — Articles
 * Severity: Medium
 *
 * Identifies published KB articles where the 'roles' field contains 'public'.
 * While this doesn't directly enable unauthenticated access (users still need
 * to authenticate), it signals intent for broad access and may interact
 * unexpectedly with glide.knowman.search.apply_role_based_security.
 *
 * Each article found should be reviewed to confirm the public role is intentional.
 *
 * Reference: https://servicenowguru.com/system-definition/controlling-public-availability-knowledge-base-content/
 */

(function(engine) {

    var articleRec = new GlideRecord('kb_knowledge');
    articleRec.addQuery('workflow_state', 'published');
    articleRec.addQuery('roles', 'CONTAINS', 'public');
    articleRec.addActiveQuery();
    articleRec.query();

    while (articleRec.next()) {
        engine.finding.setCurrentSource(articleRec);
        engine.finding.setValue('finding_details',
            'Article "' + articleRec.getValue('short_description') + '" (number: ' +
            articleRec.getValue('number') + ') in KB "' + articleRec.getDisplayValue('kb_knowledge_base') +
            '" has the "public" role set. Review whether broad public access is intentional ' +
            'for this article. The public role may interact with ' +
            'glide.knowman.search.apply_role_based_security to affect search visibility.');
        engine.finding.increment();
    }

})(engine);

/**
 * Instance Scan Check: KB pages listed in sys_public (public pages)
 * Check ID: cstaces-11n
 *
 * Type:     Script Only
 * Category: KB Security — Public Access
 * Severity: High
 *
 * Checks the sys_public table for active records allowing unauthenticated
 * access to Knowledge Base UI pages (kb_view, kb_find, kb_home, kb_list,
 * kb_comments). Any active record means unauthenticated users can reach
 * these pages without logging in.
 *
 * Reference: https://servicenowguru.com/system-definition/controlling-public-availability-knowledge-base-content/
 */

(function(engine) {

    var KB_PAGES = ['kb_view', 'kb_find', 'kb_home', 'kb_list', 'kb_comments',
                    'kb_article', 'kb_article_view', '$knowledge.do'];

    var publicPageRec = new GlideRecord('sys_public');
    publicPageRec.addActiveQuery();
    publicPageRec.addQuery('page', 'IN', KB_PAGES.join(','));
    publicPageRec.query();

    while (publicPageRec.next()) {
        engine.finding.setCurrentSource(publicPageRec);
        engine.finding.setValue('finding_details',
            'Public page "' + publicPageRec.getValue('page') + '" allows unauthenticated access to ' +
            'Knowledge Base content. Attackers can access KB portal pages without logging in, ' +
            'enabling article enumeration and data extraction. Remove this sys_public record ' +
            'unless public KB access is intentionally required.');
        engine.finding.increment();
    }

})(engine);

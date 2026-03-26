/**
 * Instance Scan Check: KBs with commenting enabled
 * Check ID: cstaces-11v
 *
 * Type:     Script Only
 * Category: KB Security — Governance
 * Severity: Low
 *
 * Identifies active knowledge bases where commenting is enabled
 * (disable_commenting = false). Comments on KB articles can be used to
 * post sensitive information, phishing links, or social engineering content.
 *
 * This is an informational check — commenting may be appropriate for
 * internal KBs but should be reviewed for externally-facing or
 * sensitive content KBs.
 */

(function(engine) {

    var kbRec = new GlideRecord('kb_knowledge_base');
    kbRec.addActiveQuery();
    kbRec.addQuery('disable_commenting', false);
    kbRec.query();

    while (kbRec.next()) {
        engine.finding.setCurrentSource(kbRec);
        engine.finding.setValue('finding_details',
            'Knowledge Base "' + kbRec.getValue('title') + '" has commenting enabled. ' +
            'Comments can be used to post sensitive data, phishing links, or misleading content. ' +
            'Review whether commenting is appropriate for this KB, especially if it is ' +
            'externally-facing or contains sensitive content. Set "Disable Commenting" to true ' +
            'if comments are not needed.');
        engine.finding.increment();
    }

})(engine);

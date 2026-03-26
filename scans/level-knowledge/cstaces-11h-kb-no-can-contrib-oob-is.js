/**
 * Instance Scan Check: KBs with no "Can Contribute" user criteria
 * Check ID: cstaces-11h
 *
 * Type:     Script Only
 * Category: KB Security — Access Control
 * Severity: Critical
 *
 * Identifies active knowledge bases with no "Can Contribute" user criteria.
 * When empty, ALL authenticated users implicitly gain contribute access, which:
 *   1. Allows any user to create, modify, and retire articles
 *   2. Grants implicit read access that bypasses article-level restrictions
 *      (unless glide.knowman.apply_article_read_criteria = true)
 *
 * This is documented as a known issue in KB0623654.
 *
 * Reference: https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0623654
 */

(function(engine) {

    var M2M_CANDIDATES = [
        'kb_uc_can_contribute_mtom',
        'm2m_kb_uc_can_contribute',
        'kb_uc_can_contribute_m2m'
    ];
    var m2mTable = '';
    for (var c = 0; c < M2M_CANDIDATES.length; c++) {
        var test = new GlideRecord(M2M_CANDIDATES[c]);
        if (test.isValid()) {
            m2mTable = M2M_CANDIDATES[c];
            break;
        }
    }

    var kbsWithCriteria = {};

    if (m2mTable) {
        var m2mRec = new GlideRecord(m2mTable);
        m2mRec.query();
        while (m2mRec.next()) {
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (kbRef) {
                kbsWithCriteria[kbRef] = true;
            }
        }
    }

    var kbListRec = new GlideRecord('kb_knowledge_base');
    kbListRec.addActiveQuery();
    kbListRec.addNotNullQuery('u_can_contribute_user_criteria');
    kbListRec.query();
    while (kbListRec.next()) {
        kbsWithCriteria[kbListRec.getUniqueValue()] = true;
    }

    var kbRec = new GlideRecord('kb_knowledge_base');
    kbRec.addActiveQuery();
    kbRec.query();

    while (kbRec.next()) {
        if (!kbsWithCriteria[kbRec.getUniqueValue()]) {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" has no "Can Contribute" user criteria. ' +
                'When empty, ALL authenticated users implicitly gain contribute access — they can create, ' +
                'modify, and retire articles. Contribute access also bypasses article-level read restrictions ' +
                'unless glide.knowman.apply_article_read_criteria is true. Define explicit contribute criteria.');
            engine.finding.increment();
        }
    }

})(engine);

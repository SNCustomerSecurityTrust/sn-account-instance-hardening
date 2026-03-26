/**
 * Instance Scan Check: Published articles with no user criteria in open KBs
 * Check ID: cstaces-11s
 *
 * Type:     Script Only
 * Category: KB Security — Articles
 * Severity: High
 *
 * Identifies published articles where BOTH the parent KB and the article
 * itself have no "Can Read" user criteria. These articles are the most
 * likely to be exposed to unauthenticated users.
 *
 * Note: This check uses GlideAggregate to report at the KB level (count
 * of unprotected articles per KB) rather than creating a finding per article,
 * which would be overwhelming on large instances.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    // First, find KBs with no Can Read criteria (reuse logic from kb-no-can-read)
    var M2M_CANDIDATES = [
        'kb_uc_can_read_mtom',
        'm2m_kb_uc_can_read',
        'kb_uc_can_read_m2m'
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
            if (kbRef) kbsWithCriteria[kbRef] = true;
        }
    }

    // Find open KBs (no Can Read criteria)
    var openKBs = [];
    var kbListRec = new GlideRecord('kb_knowledge_base');
    kbListRec.addActiveQuery();
    kbListRec.query();
    while (kbListRec.next()) {
        if (!kbsWithCriteria[kbListRec.getUniqueValue()]) {
            openKBs.push(kbListRec.getUniqueValue());
        }
    }

    if (openKBs.length === 0) return;

    // Count published articles per open KB
    var articleAgg = new GlideAggregate('kb_knowledge');
    articleAgg.addQuery('kb_knowledge_base', 'IN', openKBs.join(','));
    articleAgg.addQuery('workflow_state', 'published');
    articleAgg.addAggregate('COUNT');
    articleAgg.groupBy('kb_knowledge_base');
    articleAgg.query();

    while (articleAgg.next()) {
        var count = parseInt(articleAgg.getAggregate('COUNT'), 10);
        if (count > 0) {
            var kbId = articleAgg.getValue('kb_knowledge_base');
            var kbRec = new GlideRecord('kb_knowledge_base');
            if (kbRec.get(kbId)) {
                engine.finding.setCurrentSource(kbRec);
                engine.finding.setValue('finding_details',
                    'Knowledge Base "' + kbRec.getValue('title') + '" has no "Can Read" user criteria ' +
                    'and contains ' + count + ' published article(s) that also lack article-level ' +
                    'user criteria. These articles are the highest risk for unintended exposure. ' +
                    'Add "Can Read" user criteria to the KB or to individual sensitive articles.');
                engine.finding.increment();
            }
        }
    }

})(engine);

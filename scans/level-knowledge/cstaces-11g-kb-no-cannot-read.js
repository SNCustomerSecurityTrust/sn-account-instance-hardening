/**
 * Instance Scan Check: KBs with no "Cannot Read" user criteria
 * Check ID: cstaces-11g
 *
 * Type:     Script Only
 * Category: KB Security — Access Control
 * Severity: High
 *
 * Identifies active knowledge bases that have no "Cannot Read" user criteria.
 * Without a deny list, there is no explicit block for unauthenticated/guest users.
 * "Cannot" always overrides "Can" in user criteria evaluation, making deny lists
 * a critical defense-in-depth layer.
 *
 * The Guest User Business Rule (sys_id 6c8ec5147711111016f35c207b5a9969) only
 * applies to newly created KBs; older KBs may lack this protection.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    var M2M_CANDIDATES = [
        'kb_uc_cannot_read_mtom',
        'm2m_kb_uc_cannot_read',
        'kb_uc_cannot_read_m2m'
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
    kbListRec.addNotNullQuery('u_cannot_read_user_criteria');
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
                'Knowledge Base "' + kbRec.getValue('title') + '" has no "Cannot Read" user criteria (deny list). ' +
                'Without an explicit deny, there is no fallback block for guest/unauthenticated users. ' +
                'Add a "Cannot Read" user criteria that includes the Guest user at minimum.');
            engine.finding.increment();
        }
    }

})(engine);

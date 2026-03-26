/**
 * Instance Scan Check: KBs with no "Can Read" user criteria
 * Check ID: cstaces-11f
 *
 * Type:     Script Only
 * Category: KB Security — Access Control
 * Severity: Critical
 *
 * Identifies active knowledge bases that have no "Can Read" user criteria.
 * Without explicit read criteria, access depends entirely on the
 * glide.knowman.block_access_with_no_user_criteria property. If that
 * property is false, these KBs are accessible to everyone including guests.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    // Discover M2M table for "Can Read" criteria
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

    // Build set of KB sys_ids that have at least one "Can Read" criteria
    var kbsWithCriteria = {};

    if (m2mTable) {
        // Strategy 1: M2M table
        var m2mRec = new GlideRecord(m2mTable);
        m2mRec.query();
        while (m2mRec.next()) {
            // M2M table has a reference to kb_knowledge_base — field name varies
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (kbRef) {
                kbsWithCriteria[kbRef] = true;
            }
        }
    }

    // Strategy 2: Check Glide List field on kb_knowledge_base (fallback/supplement)
    var kbListRec = new GlideRecord('kb_knowledge_base');
    kbListRec.addActiveQuery();
    kbListRec.addNotNullQuery('u_can_read_user_criteria');
    kbListRec.query();
    while (kbListRec.next()) {
        kbsWithCriteria[kbListRec.getUniqueValue()] = true;
    }

    // Now find active KBs NOT in the set
    var kbRec = new GlideRecord('kb_knowledge_base');
    kbRec.addActiveQuery();
    kbRec.query();

    while (kbRec.next()) {
        var kbId = kbRec.getUniqueValue();
        if (!kbsWithCriteria[kbId]) {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" (' + kbRec.getValue('kb_version') +
                ') has no "Can Read" user criteria. If glide.knowman.block_access_with_no_user_criteria ' +
                'is false, this KB is accessible to ALL users including unauthenticated guests. ' +
                'Add explicit "Can Read" user criteria.');
            engine.finding.increment();
        }
    }

})(engine);

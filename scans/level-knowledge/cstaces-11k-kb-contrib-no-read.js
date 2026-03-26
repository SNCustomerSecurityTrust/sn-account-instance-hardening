/**
 * Instance Scan Check: KBs with "Can Contribute" set but no "Can Read"
 * Check ID: cstaces-11k
 *
 * Type:     Script Only
 * Category: KB Security — Access Control
 * Severity: Critical
 *
 * Identifies KBs where "Can Contribute" is configured but "Can Read" is empty.
 * This is a dangerous misconfiguration: when block_access_with_no_user_criteria
 * is true, it only blocks when NEITHER Can Read NOR Can Contribute is set.
 * If Can Contribute exists (even narrowly), the property considers the KB to
 * have criteria — so it does NOT block unauthenticated read access when
 * Can Read is missing.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    // Discover M2M tables
    var readCandidates = ['kb_uc_can_read_mtom', 'm2m_kb_uc_can_read', 'kb_uc_can_read_m2m'];
    var contribCandidates = ['kb_uc_can_contribute_mtom', 'm2m_kb_uc_can_contribute', 'kb_uc_can_contribute_m2m'];

    function findM2M(candidates) {
        for (var i = 0; i < candidates.length; i++) {
            var t = new GlideRecord(candidates[i]);
            if (t.isValid()) return candidates[i];
        }
        return '';
    }

    var readM2M = findM2M(readCandidates);
    var contribM2M = findM2M(contribCandidates);

    // Build sets
    var kbsWithRead = {};
    var kbsWithContrib = {};

    function loadKBs(tableName, targetSet) {
        if (!tableName) return;
        var m2mRec = new GlideRecord(tableName);
        m2mRec.query();
        while (m2mRec.next()) {
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (kbRef) targetSet[kbRef] = true;
        }
    }

    loadKBs(readM2M, kbsWithRead);
    loadKBs(contribM2M, kbsWithContrib);

    // Find KBs with contribute but no read
    var kbRec = new GlideRecord('kb_knowledge_base');
    kbRec.addActiveQuery();
    kbRec.query();

    while (kbRec.next()) {
        var kbId = kbRec.getUniqueValue();
        if (kbsWithContrib[kbId] && !kbsWithRead[kbId]) {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" has "Can Contribute" user criteria defined ' +
                'but no "Can Read" user criteria. This is a dangerous gap: the ' +
                'glide.knowman.block_access_with_no_user_criteria property considers this KB to have ' +
                'criteria (because Can Contribute exists) and will NOT block access — but no Can Read ' +
                'restriction exists, so unauthenticated users may still read articles. ' +
                'Add explicit "Can Read" user criteria.');
            engine.finding.increment();
        }
    }

})(engine);

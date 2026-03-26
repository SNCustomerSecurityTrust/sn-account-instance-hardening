/**
 * Instance Scan Check: KBs using "Any User" or "Any user for kb" in Can Read
 * Check ID: cstaces-11i
 *
 * Type:     Script Only
 * Category: KB Security — Access Control
 * Severity: Critical
 *
 * Identifies knowledge bases where "Can Read" includes the built-in
 * "Any User" or "Any user for kb" user criteria records. These match
 * ALL users including unauthenticated/guest — administrators commonly
 * mistake them for "all authenticated employees."
 *
 * This was one of three root cause scenarios for KB data exposure per AppOmni.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    // Find the "Any User" and "Any user for kb" user criteria records
    var dangerousCriteria = {};
    var ucRec = new GlideRecord('user_criteria');
    ucRec.addEncodedQuery('nameINAny User,Any user for kb');
    ucRec.query();
    while (ucRec.next()) {
        dangerousCriteria[ucRec.getUniqueValue()] = ucRec.getValue('name');
    }

    if (Object.keys(dangerousCriteria).length === 0) {
        return; // No dangerous criteria records found on this instance
    }

    // Check M2M tables for "Can Read" relationships
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

    var flaggedKBs = {}; // kbId -> criteriaName

    if (m2mTable) {
        var m2mRec = new GlideRecord(m2mTable);
        m2mRec.query();
        while (m2mRec.next()) {
            var ucRef = m2mRec.getValue('user_criteria') || m2mRec.getValue('user_criteria_id') || '';
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (ucRef && kbRef && dangerousCriteria[ucRef]) {
                flaggedKBs[kbRef] = dangerousCriteria[ucRef];
            }
        }
    }

    // Report findings
    for (var kbId in flaggedKBs) {
        var kbRec = new GlideRecord('kb_knowledge_base');
        if (kbRec.get(kbId) && kbRec.getValue('active') === 'true') {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" uses "' + flaggedKBs[kbId] +
                '" in its "Can Read" user criteria. This built-in criteria matches ALL users ' +
                'including unauthenticated guests. Replace with a criteria targeting specific ' +
                'roles or groups (e.g., all employees via a common role like snc_internal).');
            engine.finding.increment();
        }
    }

})(engine);

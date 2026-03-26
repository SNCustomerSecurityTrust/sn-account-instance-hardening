/**
 * Instance Scan Check: Guest user not in "Cannot Read" for non-public KBs
 * Check ID: cstaces-11j
 *
 * Type:     Script Only
 * Category: KB Security — Access Control
 * Severity: High
 *
 * Identifies active knowledge bases where the Guest user is not included
 * in any "Cannot Read" user criteria. Since "Cannot" overrides "Can" in
 * ServiceNow's evaluation, having Guest in "Cannot Read" is a critical
 * safety net even if "Can Read" accidentally includes broad criteria.
 *
 * The OOB Business Rule (sys_id 6c8ec5147711111016f35c207b5a9969) adds
 * Guest to Cannot Read on new KBs, but older KBs may lack this protection.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    // Find the Guest user sys_id
    var guestId = '';
    var guestRec = new GlideRecord('sys_user');
    guestRec.addQuery('user_name', 'guest');
    guestRec.query();
    if (guestRec.next()) {
        guestId = guestRec.getUniqueValue();
    }
    if (!guestId) {
        return; // No guest user found
    }

    // Find all user criteria that include the Guest user
    var criteriaWithGuest = {};
    var ucRec = new GlideRecord('user_criteria');
    ucRec.addQuery('users', 'CONTAINS', guestId);
    ucRec.query();
    while (ucRec.next()) {
        criteriaWithGuest[ucRec.getUniqueValue()] = true;
    }

    // Check M2M tables for "Cannot Read" relationships
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

    var kbsProtected = {};

    if (m2mTable) {
        var m2mRec = new GlideRecord(m2mTable);
        m2mRec.query();
        while (m2mRec.next()) {
            var ucRef = m2mRec.getValue('user_criteria') || m2mRec.getValue('user_criteria_id') || '';
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (ucRef && kbRef && criteriaWithGuest[ucRef]) {
                kbsProtected[kbRef] = true;
            }
        }
    }

    // Find active KBs that are NOT protected
    var kbRec = new GlideRecord('kb_knowledge_base');
    kbRec.addActiveQuery();
    kbRec.query();

    while (kbRec.next()) {
        if (!kbsProtected[kbRec.getUniqueValue()]) {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" does not have the Guest user in any ' +
                '"Cannot Read" user criteria. Without an explicit Guest deny, unauthenticated users ' +
                'may access this KB if other conditions allow it (e.g., "Any User" in Can Read, or ' +
                'no user criteria at all). Add Guest to a "Cannot Read" user criteria on this KB.');
            engine.finding.increment();
        }
    }

})(engine);

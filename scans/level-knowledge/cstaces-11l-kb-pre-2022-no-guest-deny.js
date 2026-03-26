/**
 * Instance Scan Check: KBs created before mid-2022 without Guest deny
 * Check ID: cstaces-11l
 *
 * Type:     Script Only
 * Category: KB Security — Access Control
 * Severity: High
 *
 * Identifies knowledge bases created before mid-2022 (when the Guest User
 * Business Rule was introduced) that do not have Guest in their "Cannot Read"
 * criteria. These are the highest-risk KBs for unintended public exposure
 * since the automatic protection was not applied retroactively.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    var CUTOFF_DATE = '2022-07-01 00:00:00';

    // Find Guest user
    var guestId = '';
    var guestRec = new GlideRecord('sys_user');
    guestRec.addQuery('user_name', 'guest');
    guestRec.query();
    if (guestRec.next()) guestId = guestRec.getUniqueValue();
    if (!guestId) return;

    // Find criteria that include Guest
    var criteriaWithGuest = {};
    var ucRec = new GlideRecord('user_criteria');
    ucRec.addQuery('users', 'CONTAINS', guestId);
    ucRec.query();
    while (ucRec.next()) {
        criteriaWithGuest[ucRec.getUniqueValue()] = true;
    }

    // Check Cannot Read M2M
    var M2M_CANDIDATES = ['kb_uc_cannot_read_mtom', 'm2m_kb_uc_cannot_read', 'kb_uc_cannot_read_m2m'];
    var m2mTable = '';
    for (var c = 0; c < M2M_CANDIDATES.length; c++) {
        var test = new GlideRecord(M2M_CANDIDATES[c]);
        if (test.isValid()) { m2mTable = M2M_CANDIDATES[c]; break; }
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

    // Find pre-2022 KBs without Guest deny
    var kbRec = new GlideRecord('kb_knowledge_base');
    kbRec.addActiveQuery();
    kbRec.addQuery('sys_created_on', '<', CUTOFF_DATE);
    kbRec.query();

    while (kbRec.next()) {
        if (!kbsProtected[kbRec.getUniqueValue()]) {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" was created on ' +
                kbRec.getValue('sys_created_on') + ' (before the Guest User Business Rule was introduced ' +
                'in mid-2022) and does not have the Guest user in any "Cannot Read" user criteria. ' +
                'This KB was not retroactively protected and is at elevated risk for unauthenticated ' +
                'access. Add Guest to a "Cannot Read" user criteria immediately.');
            engine.finding.increment();
        }
    }

})(engine);

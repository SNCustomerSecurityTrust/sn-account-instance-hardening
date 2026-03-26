/**
 * Instance Scan Check: Scripted (advanced) user criteria applied to KBs
 * Check ID: cstaces-11u
 *
 * Type:     Script Only
 * Category: KB Security — User Criteria
 * Severity: Medium
 *
 * Identifies user criteria records with "Advanced" (scripted) evaluation
 * that are applied to knowledge bases. Scripted criteria are:
 *   - Cached at session level only (not application level) — performance hit
 *   - Harder to audit — cannot determine who matches without running the script
 *   - May contain logic bugs that inadvertently grant or deny access
 *
 * Best practice: extend the user_criteria table with additional fields instead.
 *
 * Reference: https://www.servicenow.com/community/itsm-blog/scripts-in-user-criteria/ba-p/2294597
 */

(function(engine) {

    // Find all scripted user criteria
    var scriptedUC = {};
    var ucRec = new GlideRecord('user_criteria');
    ucRec.addQuery('advanced', true);
    ucRec.addActiveQuery();
    ucRec.query();
    while (ucRec.next()) {
        scriptedUC[ucRec.getUniqueValue()] = ucRec.getValue('name');
    }

    if (Object.keys(scriptedUC).length === 0) return;

    // Check all M2M tables for these criteria being used on KBs
    var M2M_TABLES = [
        'kb_uc_can_read_mtom', 'm2m_kb_uc_can_read', 'kb_uc_can_read_m2m',
        'kb_uc_cannot_read_mtom', 'm2m_kb_uc_cannot_read', 'kb_uc_cannot_read_m2m',
        'kb_uc_can_contribute_mtom', 'm2m_kb_uc_can_contribute', 'kb_uc_can_contribute_m2m',
        'kb_uc_cannot_contribute_mtom', 'm2m_kb_uc_cannot_contribute', 'kb_uc_cannot_contribute_m2m'
    ];

    var findings = {}; // kbId -> [criteriaNames]

    for (var t = 0; t < M2M_TABLES.length; t++) {
        var m2mRec = new GlideRecord(M2M_TABLES[t]);
        if (!m2mRec.isValid()) continue;
        m2mRec.query();
        while (m2mRec.next()) {
            var ucRef = m2mRec.getValue('user_criteria') || m2mRec.getValue('user_criteria_id') || '';
            var kbRef = m2mRec.getValue('kb_knowledge_base') || m2mRec.getValue('kb_knowledge_base_id') || '';
            if (ucRef && kbRef && scriptedUC[ucRef]) {
                if (!findings[kbRef]) findings[kbRef] = [];
                if (findings[kbRef].indexOf(scriptedUC[ucRef]) < 0) {
                    findings[kbRef].push(scriptedUC[ucRef]);
                }
            }
        }
    }

    // Report findings per KB
    for (var kbId in findings) {
        var kbRec = new GlideRecord('kb_knowledge_base');
        if (kbRec.get(kbId) && kbRec.getValue('active') === 'true') {
            engine.finding.setCurrentSource(kbRec);
            engine.finding.setValue('finding_details',
                'Knowledge Base "' + kbRec.getValue('title') + '" uses ' +
                findings[kbId].length + ' scripted (advanced) user criteria: ' +
                findings[kbId].join(', ') + '. Scripted criteria are cached at session level ' +
                'only (degraded performance), are difficult to audit, and may contain logic bugs. ' +
                'Consider replacing with field-based criteria by extending the user_criteria table.');
            engine.finding.increment();
        }
    }

})(engine);

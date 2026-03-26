/**
 * Instance Scan Check: Custom ACLs on kb_knowledge that may override user criteria
 * Check ID: cstaces-11r
 *
 * Type:     Script Only
 * Category: KB Security — ACLs
 * Severity: Medium
 *
 * Identifies non-OOB (custom) ACL records on the kb_knowledge table.
 * Custom ACLs can inadvertently grant broader access than user criteria intend.
 * For example, an ACL granting 'admin' or 'itil' read access without checking
 * user criteria bypasses all KB-level and article-level restrictions.
 *
 * ACLs with a populated security_attribute field are excluded — the Security
 * Attribute provides its own access control evaluation.
 *
 * This check flags custom ACLs for review — not all are problematic, but
 * each should be validated against the intended KB access model.
 *
 * Reference: https://www.servicenow.com/community/developer-forum/acl-overriding-user-criteria-for-knowledge-base/m-p/3110308
 */

(function(engine) {

    var aclRec = new GlideRecord('sys_security_acl');
    aclRec.addQuery('name', 'CONTAINS', 'kb_knowledge');
    aclRec.addQuery('active', true);
    aclRec.addQuery('sys_policy', ''); // Empty sys_policy typically means custom/non-protected
    aclRec.query();

    while (aclRec.next()) {
        // If security_attribute is populated, the ACL delegates to a
        // Security Attribute check — skip it
        var secAttr = aclRec.getValue('security_attribute') || '';
        if (secAttr) continue;

        // Check if this is likely a custom ACL (not part of a plugin/app)
        var scope = aclRec.getValue('sys_scope') || '';
        var updateName = aclRec.getValue('sys_update_name') || '';

        // Flag ACLs not in the 'sn_km' or 'global' scope with known patterns
        // This is a heuristic — we flag for review, not as definitively wrong
        var isLikelyCustom = updateName.indexOf('sys_security_acl_') === 0 &&
            scope !== '' &&
            scope.indexOf('sn_km') < 0;

        // Also flag if the ACL was created after the instance was set up (custom addition)
        var created = aclRec.getValue('sys_created_on') || '';

        if (isLikelyCustom) {
            engine.finding.setCurrentSource(aclRec);
            engine.finding.setValue('finding_details',
                'Custom ACL "' + aclRec.getValue('name') + '" (operation: ' + aclRec.getValue('operation') +
                ', scope: ' + scope + ') exists on the kb_knowledge table. ' +
                'Custom ACLs can override user criteria restrictions — a user blocked by user criteria ' +
                'may still access articles if an ACL grants them access. Review this ACL to ensure it ' +
                'does not bypass intended KB access controls.');
            engine.finding.increment();
        }
    }

})(engine);

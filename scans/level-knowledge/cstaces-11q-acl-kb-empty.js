/**
 * Instance Scan Check: Empty ACLs on kb_knowledge table
 * Check ID: cstaces-11q
 *
 * Type:     Script Only
 * Category: KB Security — ACLs
 * Severity: High
 *
 * Identifies ACL records for the kb_knowledge table where role, condition,
 * script, AND security_attribute are all empty — granting unrestricted access.
 * If security_attribute is populated, the ACL delegates to a Security Attribute
 * check and is not considered empty. While KB v3 primarily uses user criteria
 * for access control, truly empty ACLs on the underlying table create a bypass
 * path (e.g., via SimpleListWidget).
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 * Reference: https://www.obsidiansecurity.com/blog/are-your-servicenow-lists-publicly-exposing-data
 */

(function(engine) {

    var aclRec = new GlideRecord('sys_security_acl');
    aclRec.addQuery('name', 'CONTAINS', 'kb_knowledge');
    aclRec.addQuery('active', true);
    aclRec.query();

    while (aclRec.next()) {
        var hasRole = false;
        var hasCondition = aclRec.getValue('condition') !== '' && aclRec.getValue('condition') !== null;
        var hasScript = aclRec.getValue('script') !== '' && aclRec.getValue('script') !== null;
        var hasSecAttr = aclRec.getValue('security_attribute') !== '' && aclRec.getValue('security_attribute') !== null;

        // If security_attribute is populated, the ACL delegates to a
        // Security Attribute check — not considered empty
        if (hasSecAttr) continue;

        // Check if ACL has any role requirements
        var aclRoleRec = new GlideRecord('sys_security_acl_role');
        aclRoleRec.addQuery('sys_security_acl', aclRec.getUniqueValue());
        aclRoleRec.query();
        hasRole = aclRoleRec.hasNext();

        if (!hasRole && !hasCondition && !hasScript) {
            engine.finding.setCurrentSource(aclRec);
            engine.finding.setValue('finding_details',
                'ACL "' + aclRec.getValue('name') + '" (operation: ' + aclRec.getValue('operation') +
                ') on the kb_knowledge table has no role, no condition, and no script — ' +
                'granting unrestricted access. This can be exploited via direct list access ' +
                'or widgets like SimpleListWidget to bypass user criteria restrictions. ' +
                'Add appropriate role requirements or conditions to this ACL.');
            engine.finding.increment();
        }
    }

})(engine);

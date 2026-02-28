/**
 * Query 2a: Overly Permissive ACLs
 *
 * Purpose:
 * Identifies active ACLs that have no role restrictions, no conditions, and no
 * scripts - meaning any authenticated user can pass them regardless of their
 * role or context. These represent the most common form of misconfigured access
 * control in ServiceNow instances that have grown organically without periodic
 * ACL reviews.
 *
 * What it checks:
 * - Builds a lookup of all ACLs that have at least one role assigned via
 *   sys_security_acl_role to avoid N+1 query overhead
 * - Queries active ACLs with null condition and null script
 * - Excludes read-only locked records (sys_policy = read) to reduce OOB noise
 * - Skips any ACL that has role restrictions from the lookup
 * - Categorizes remaining ACLs by operation risk level:
 *     CRITICAL - Wildcard operation (*) with no restrictions
 *     HIGH - Write, create, or delete with no restrictions
 *     MEDIUM - Read with no restrictions
 *     LOW - Other operations with no restrictions
 * - Results sorted by risk level for triage
 *
 * Risk context:
 * CRITICAL findings mean any authenticated user can perform any operation on
 * the affected table or field with no access control enforcement whatsoever.
 * HIGH findings expose write, create, and delete operations to all users which
 * can lead to unauthorized data modification or destruction. MEDIUM findings
 * expose data to all authenticated users which may violate data privacy
 * requirements. The sys_update_name field helps distinguish customer
 * customizations from out of box records when prioritizing remediation.
 *
 * Known false positive patterns:
 * Some OOB ServiceNow ACLs are intentionally permissive for public facing
 * tables or service portal functionality. The sys_scope and sys_update_name
 * fields help identify whether a finding is OOB or a customization. OOB
 * permissive ACLs should still be documented as accepted risk even if not
 * remediated. The sys_policy filter reduces but does not eliminate OOB noise.
 *
 * Remediation guidance:
 * CRITICAL - Add role restrictions or conditions immediately. Wildcard operation
 * ACLs with no controls should be treated as active vulnerabilities. HIGH -
 * Review each write, create, and delete ACL and add the minimum required role
 * restriction. MEDIUM - Review read ACLs against data classification and add
 * role restrictions where sensitive data is exposed. All findings should be
 * reviewed against documented business requirements before remediation to avoid
 * breaking legitimate functionality.
 *
 * Tables queried: sys_security_acl_role, sys_security_acl
 */

(function findOverlyPermissiveACLs() {

    var riskyACLs = [];
    var aclsWithRoles = {};

    // Step 1: Build lookup of ACLs that have role restrictions
    // Avoids N+1 query problem by pre-loading all role assignments
    var roleGR = new GlideRecord('sys_security_acl_role');
    roleGR.addNotNullQuery('sys_security_acl');
    roleGR.query();
    while (roleGR.next()) {
        aclsWithRoles[roleGR.sys_security_acl.toString()] = true;
    }

    // Step 2: Query active ACLs with no condition and no script
    var gr = new GlideRecord('sys_security_acl');
    gr.addQuery('active', 'true');
    gr.addNullQuery('condition');
    gr.addNullQuery('script');
    gr.addQuery('sys_policy', '!=', 'read'); // exclude read-only locked OOB records
    gr.query();

    while (gr.next()) {
        var sysId = gr.sys_id.toString();

        // Skip ACLs that have role restrictions
        if (aclsWithRoles[sysId]) {
            continue;
        }

        var operation = gr.operation.toString();
        var riskLevel = 'LOW';

        if (operation === '*') {
            riskLevel = 'CRITICAL'; // Wildcard operation with no controls
        } else if (operation === 'write' || operation === 'create' || operation === 'delete') {
            riskLevel = 'HIGH';
        } else if (operation === 'read') {
            riskLevel = 'MEDIUM';
        }

        riskyACLs.push({
            sys_id: sysId,
            name: gr.name.toString(),
            type: gr.type.toString(),
            operation: operation,
            admin_overrides: gr.admin_overrides.toString(),
            risk_level: riskLevel,
            sys_scope: gr.sys_scope.getDisplayValue(),
            sys_update_name: gr.sys_update_name.toString()
        });
    }

    // Sort by risk level for triage
    var riskOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 };
    riskyACLs.sort(function(a, b) {
        return riskOrder[a.risk_level] - riskOrder[b.risk_level];
    });

    gs.info('=== OVERLY PERMISSIVE ACL SCAN ===');
    gs.info('Total findings: ' + riskyACLs.length);
    gs.info('CRITICAL: ' + riskyACLs.filter(function(a) { return a.risk_level === 'CRITICAL'; }).length);
    gs.info('HIGH: ' + riskyACLs.filter(function(a) { return a.risk_level === 'HIGH'; }).length);
    gs.info('MEDIUM: ' + riskyACLs.filter(function(a) { return a.risk_level === 'MEDIUM'; }).length);
    gs.info('LOW: ' + riskyACLs.filter(function(a) { return a.risk_level === 'LOW'; }).length);
    gs.info('Full results: ' + JSON.stringify(riskyACLs, null, 2));

})();
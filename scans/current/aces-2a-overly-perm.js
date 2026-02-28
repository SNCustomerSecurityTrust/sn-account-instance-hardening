(function(engine) {


    var riskyACLs = [];
    var aclsWithRoles = {};

    // Build lookup of ACLs that have role restrictions to avoid N+1 query overhead
    var aclRoleEntry = new GlideRecord('sys_security_acl_role');
    aclRoleEntry.addNotNullQuery('sys_security_acl');
    aclRoleEntry.query();
    while (aclRoleEntry.next()) {
        aclsWithRoles[aclRoleEntry.sys_security_acl.toString()] = true;
    }

    // Query active ACLs with no condition and no script
    var aclRecord = new GlideRecord('sys_security_acl');
    aclRecord.addQuery('active', 'true');
    aclRecord.addNullQuery('condition');
    aclRecord.addNullQuery('script');
    aclRecord.addQuery('sys_policy', '!=', 'read'); // Exclude read-only locked OOB records
    aclRecord.query();

    while (aclRecord.next()) {
        var sysId = aclRecord.sys_id.toString();

        // Skip ACLs that have role restrictions
        if (aclsWithRoles[sysId]) {
            continue;
        }

        var operation = aclRecord.operation.toString();
        var riskLevel = 'LOW';

		engine.finding.setCurrentSource(aclRecord);
		engine.finding.increment();


        if (operation === '*') {
            riskLevel = 'CRITICAL'; // Wildcard operation with no controls whatsoever
        } else if (operation === 'write' || operation === 'create' || operation === 'delete') {
            riskLevel = 'HIGH';
        } else if (operation === 'read') {
            riskLevel = 'MEDIUM';
        }

        riskyACLs.push({
            sys_id: sysId,
            name: aclRecord.name.toString(),
            type: aclRecord.type.toString(),
            operation: operation,
            admin_overrides: aclRecord.admin_overrides.toString(),
            risk_level: riskLevel,
            sys_scope: aclRecord.sys_scope.getDisplayValue(),
            sys_update_name: aclRecord.sys_update_name.toString()
        });
    }

    // Sort by risk level for triage
    var riskOrder = {
        'CRITICAL': 0,
        'HIGH': 1,
        'MEDIUM': 2,
        'LOW': 3
    };
    riskyACLs.sort(function(a, b) {
        return riskOrder[a.risk_level] - riskOrder[b.risk_level];
    });

    // gs.info('=== OVERLY PERMISSIVE ACL SCAN ===');
    // gs.info('Total findings: ' + riskyACLs.length);
    // gs.info('CRITICAL: ' + riskyACLs.filter(function(a) {
    //     return a.risk_level === 'CRITICAL';
    // }).length);
    // gs.info('HIGH: ' + riskyACLs.filter(function(a) {
    //     return a.risk_level === 'HIGH';
    // }).length);
    // gs.info('MEDIUM: ' + riskyACLs.filter(function(a) {
    //     return a.risk_level === 'MEDIUM';
    // }).length);
    // gs.info('LOW: ' + riskyACLs.filter(function(a) {
    //     return a.risk_level === 'LOW';
    // }).length);
    // gs.info('Full results: ' + JSON.stringify(riskyACLs, null, 2));



})(engine);
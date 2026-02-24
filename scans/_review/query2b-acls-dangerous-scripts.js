/**
 * Query 2b: ACLs with Complex/Dangerous Scripts
 *
 * Purpose:
 * Identifies active ACLs containing script patterns that indicate dangerous,
 * overly permissive, or poorly written access control logic.
 *
 * What it checks:
 * Scans all active ACLs with non-null scripts against a pattern library
 * grouped by concern level. Patterns include unconditional grants, admin
 * role bypass attempts, dynamic behavior driven by external scripts or
 * system properties, and incomplete or disabled logic markers. Results
 * are deduplicated by sys_id, sorted by highest concern first, and include
 * a 300-character script preview for triage.
 *
 * Known false positive patterns:
 * Some legitimate ACL scripts may conditionally return true based on valid
 * business logic that matches a pattern. Always review the full script
 * context before treating a finding as confirmed.
 *
 * Tables queried: sys_security_acl
 */

(function findDangerousACLScripts() {

    var patterns = {
        UNCONDITIONAL_GRANT: [
            'answer = true',
            'answer=true',
            'return true'
        ],
        BYPASS_PATTERN: [
            'gs.getuser().hasrole(\'admin\')',
            'gs.hasrole(\'admin\')',
            'gs.getuser().isuseringroup',
            'current.setabortaction(false)',
            'gs.nil('
        ],
        DYNAMIC_BEHAVIOR: [
            'gs.getproperty(',
            'new glidescript(',
            'gs.includescript(',
            'javascriptprobe'
        ],
        INCOMPLETE_LOGIC: [
            '//answer',
            '/* answer',
            'todo',
            'fixme',
            'hardcoded'
        ]
    };

    var concernOrder = ['UNCONDITIONAL_GRANT', 'BYPASS_PATTERN', 'DYNAMIC_BEHAVIOR', 'INCOMPLETE_LOGIC'];
    var suspiciousACLs = {};

    var gr = new GlideRecord('sys_security_acl');
    gr.addQuery('active', 'true');
    gr.addNotNullQuery('script');
    gr.query();

    while (gr.next()) {
        var script = gr.script.toString();
        var scriptLower = script.toLowerCase().replace(/\s+/g, ' ');
        var sysId = gr.sys_id.toString();

        var matchedPatterns = [];
        var highestConcern = null;

        for (var category in patterns) {
            var patternList = patterns[category];
            for (var i = 0; i < patternList.length; i++) {
                if (scriptLower.indexOf(patternList[i]) > -1) {
                    matchedPatterns.push({
                        pattern: patternList[i],
                        category: category
                    });
                    if (highestConcern === null ||
                        concernOrder.indexOf(category) < concernOrder.indexOf(highestConcern)) {
                        highestConcern = category;
                    }
                }
            }
        }

        if (matchedPatterns.length > 0) {
            suspiciousACLs[sysId] = {
                sys_id: sysId,
                name: gr.name.toString(),
                table: gr.name.toString().split('.')[0],
                operation: gr.operation.toString(),
                highest_concern: highestConcern,
                matched_patterns: matchedPatterns,
                admin_overrides: gr.admin_overrides.toString(),
                sys_scope: gr.sys_scope.getDisplayValue(),
                sys_update_name: gr.sys_update_name.toString(),
                script_preview: script.substring(0, 300)
            };
        }
    }

    var results = [];
    for (var id in suspiciousACLs) {
        results.push(suspiciousACLs[id]);
    }
    results.sort(function(a, b) {
        return concernOrder.indexOf(a.highest_concern) - concernOrder.indexOf(b.highest_concern);
    });

    gs.info('=== ACL DANGEROUS SCRIPT SCAN ===');
    gs.info('Total findings: ' + results.length);
    gs.info('Unconditional grants: ' + results.filter(function(a) { return a.highest_concern === 'UNCONDITIONAL_GRANT'; }).length);
    gs.info('Bypass patterns: ' + results.filter(function(a) { return a.highest_concern === 'BYPASS_PATTERN'; }).length);
    gs.info('Dynamic behavior: ' + results.filter(function(a) { return a.highest_concern === 'DYNAMIC_BEHAVIOR'; }).length);
    gs.info('Incomplete logic: ' + results.filter(function(a) { return a.highest_concern === 'INCOMPLETE_LOGIC'; }).length);
    gs.info(JSON.stringify(results, null, 2));

})();
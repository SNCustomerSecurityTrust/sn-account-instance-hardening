(function (engine) {


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

    var aclRecord = new GlideRecord('sys_security_acl');
    aclRecord.addQuery('active', 'true');
    aclRecord.addNotNullQuery('script');
    aclRecord.query();

    while (aclRecord.next()) {
        var script = aclRecord.script.toString();
        var scriptLower = script.toLowerCase().replace(/\s+/g, ' ');
        var sysId = aclRecord.sys_id.toString();

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

					engine.finding.setCurrentSource(aclRecord);
					engine.finding.setValue('finding_details', JSON.stringify(matchedPatterns));
					engine.finding.increment();

                }
            }
        }

        if (matchedPatterns.length > 0) {
            suspiciousACLs[sysId] = {
                sys_id: sysId,
                name: aclRecord.name.toString(),
                table: aclRecord.name.toString().split('.')[0],
                operation: aclRecord.operation.toString(),
                highest_concern: highestConcern,
                matched_patterns: matchedPatterns,
                admin_overrides: aclRecord.admin_overrides.toString(),
                sys_scope: aclRecord.sys_scope.getDisplayValue(),
                sys_update_name: aclRecord.sys_update_name.toString(),
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

    // gs.info('=== ACL DANGEROUS SCRIPT SCAN ===');
    // gs.info('Total findings: ' + results.length);
    // gs.info('Unconditional grants: ' + results.filter(function(a) { return a.highest_concern === 'UNCONDITIONAL_GRANT'; }).length);
    // gs.info('Bypass patterns: ' + results.filter(function(a) { return a.highest_concern === 'BYPASS_PATTERN'; }).length);
    // gs.info('Dynamic behavior: ' + results.filter(function(a) { return a.highest_concern === 'DYNAMIC_BEHAVIOR'; }).length);
    // gs.info('Incomplete logic: ' + results.filter(function(a) { return a.highest_concern === 'INCOMPLETE_LOGIC'; }).length);
    // gs.info(JSON.stringify(results, null, 2));



})(engine);
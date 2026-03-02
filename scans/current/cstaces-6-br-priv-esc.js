(function(engine) {


    //var sw = new GlideStopWatch();

    var businessRule = new GlideRecord('sys_script');
    businessRule.addQuery('active', 'true');
    businessRule.addQuery('when', 'IN', 'before,after,async,display');
    businessRule.query();

    //gs.info('Scanning ' + businessRule.getRowCount() + ' active business rules...\n');

    var systemRules = [];
    var dangerousPatterns = [
        'gs.setProperty',
        'GlideRecord(\'sys_user\')',
        'GlideRecord("sys_user")',
        'current.setAbortAction(false)',
        'gs.getUser().setRole',
        'gs.addRole',
        'gs.nil(',
        'GlideRecord(\'sys_user_has_role\')',
        'GlideRecord("sys_user_has_role")',
        'gs.getSession().putClientData',
        'answer = true;'
    ];

    while (businessRule.next()) {
        var script = businessRule.script.toString();
        var matchedPatterns = [];

        for (var i = 0; i < dangerousPatterns.length; i++) {
            if (script.indexOf(dangerousPatterns[i]) > -1) {
                matchedPatterns.push(dangerousPatterns[i]);
            }
        }

        if (matchedPatterns.length > 0) {

			
			var brMatchedPatternObj = {
                name: businessRule.name.toString(),
                table: businessRule.collection.toString(),
                when: businessRule.when.toString(),
                active: businessRule.active.toString(),
                sys_id: businessRule.sys_id.toString(),
                matched_patterns: matchedPatterns,
                pattern_count: matchedPatterns.length
            };

            systemRules.push(brMatchedPatternObj);

			engine.finding.setCurrentSource(businessRule);
			engine.finding.setValue('finding_details',JSON.stringify(brMatchedPatternObj));
			engine.finding.increment();

        }
    }

    //gs.info('Scan completed in: ' + sw.elapsed() + 'ms');
    //gs.warn('\nFound ' + systemRules.length + ' business rules with potential privilege escalation patterns\n');

    // for (var j = 0; j < systemRules.length; j++) {
    //     var rule = systemRules[j];
    //     gs.warn('---');
    //     gs.warn('Business Rule: ' + rule.name);
    //     gs.warn('Table: ' + rule.table);
    //     gs.warn('When: ' + rule.when);
    //     gs.warn('Patterns found: ' + rule.matched_patterns.join(', '));
    //     gs.warn('Sys ID: ' + rule.sys_id);
    // }

    //gs.info('\n=== JSON Export ===');
    //gs.info(JSON.stringify(systemRules, null, 2));

    return systemRules;




})(engine);

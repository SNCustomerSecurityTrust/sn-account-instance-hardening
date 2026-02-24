
//Q6 Business Logic running with system privileges

/**
 * Audit Business Rules for Privilege Escalation Patterns
 * Run in: Scripts - Background
 */

(function auditBusinessRules() {
    try {
        var sw = new GlideStopWatch();
        
        // Query business rules
        var gr = new GlideRecord('sys_script');
        gr.addQuery('active', 'true');
        gr.addQuery('when', 'IN', 'before,after,async,display');
        gr.query();
        
        gs.info('Scanning ' + gr.getRowCount() + ' active business rules...\n');
        
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
            'answer = true;' // Suspicious in conditions
        ];
        
        while (gr.next()) {
            var script = gr.script.toString();
            var matchedPatterns = [];
            
            // Check for each dangerous pattern
            for (var i = 0; i < dangerousPatterns.length; i++) {
                if (script.indexOf(dangerousPatterns[i]) > -1) {
                    matchedPatterns.push(dangerousPatterns[i]);
                }
            }
            
            // If any patterns found, add to results
            if (matchedPatterns.length > 0) {
                systemRules.push({
                    name: gr.name.toString(),
                    table: gr.collection.toString(),
                    when: gr.when.toString(),
                    active: gr.active.toString(),
                    sys_id: gr.sys_id.toString(),
                    matched_patterns: matchedPatterns,
                    pattern_count: matchedPatterns.length
                });
            }
        }
        
        // Output results
        gs.info('Scan completed in: ' + sw.elapsed() + 'ms');
        gs.warn('\nFound ' + systemRules.length + ' business rules with potential privilege escalation patterns\n');
        
        // Detailed output
        for (var j = 0; j < systemRules.length; j++) {
            var rule = systemRules[j];
            gs.warn('---');
            gs.warn('Business Rule: ' + rule.name);
            gs.warn('Table: ' + rule.table);
            gs.warn('When: ' + rule.when);
            gs.warn('Patterns found: ' + rule.matched_patterns.join(', '));
            gs.warn('Sys ID: ' + rule.sys_id);
        }
        
        // JSON export
        gs.info('\n=== JSON Export ===');
        gs.info(JSON.stringify(systemRules, null, 2));
        
        return systemRules;
        
    } catch (e) {
        gs.error('Error during business rule audit: ' + e.message);
        gs.error('Line: ' + e.lineNumber);
        return null;
    }
})();
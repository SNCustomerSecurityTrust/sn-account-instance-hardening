/**
 * Instance Scan Check: Guest User Business Rule is inactive
 * Check ID: cstaces-11m
 *
 * Type:     Script Only
 * Category: KB Security — Configuration
 * Severity: High
 *
 * Checks that the OOB Business Rule (sys_id 6c8ec5147711111016f35c207b5a9969)
 * which adds the Guest User to "Cannot Read" and "Cannot Contribute" on newly
 * created KBs is active. If deactivated (e.g., during troubleshooting and
 * never re-enabled), new KBs will not automatically be protected from
 * unauthenticated access.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    var BR_SYS_ID = '6c8ec5147711111016f35c207b5a9969';

    var brRec = new GlideRecord('sys_script');
    if (brRec.get(BR_SYS_ID)) {
        if (brRec.getValue('active') !== '1') {
            engine.finding.setCurrentSource(brRec);
            engine.finding.setValue('finding_details',
                'The Guest User Business Rule (sys_id ' + BR_SYS_ID + ') is INACTIVE. ' +
                'This Business Rule automatically adds the Guest user to "Cannot Read" and ' +
                '"Cannot Contribute" user criteria when a new Knowledge Base is created. ' +
                'Without it, newly created KBs will not be protected from unauthenticated access. ' +
                'Re-activate this Business Rule immediately.');
            engine.finding.increment();
        }
    } else {
        // BR doesn't exist — may be a very old instance or it was deleted
        var brRec2 = new GlideRecord('sys_script');
        brRec2.addQuery('sys_id', BR_SYS_ID);
        brRec2.query();
        engine.finding.setCurrentSource(brRec2);
        engine.finding.setValue('finding_details',
            'The Guest User Business Rule (sys_id ' + BR_SYS_ID + ') was not found on this instance. ' +
            'This OOB rule adds Guest to "Cannot Read" and "Cannot Contribute" on new KBs. ' +
            'It may not exist on older instances. Consider creating equivalent protection manually.');
        engine.finding.increment();
    }

})(engine);

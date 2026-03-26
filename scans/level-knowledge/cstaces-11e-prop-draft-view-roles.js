/**
 * Instance Scan Check: glide.knowman.section.view_roles.draft
 * Check ID: cstaces-11e
 *
 * Type:     Script Only
 * Category: KB Security — System Properties
 * Severity: Medium
 *
 * Checks that glide.knowman.section.view_roles.draft is not overly permissive.
 * If set to a common role (like 'itil') or left empty, draft articles are
 * visible to a broad audience before they've been reviewed and approved.
 *
 * Expected: Restrictive roles like 'knowledge' or 'knowledge_admin'.
 */

(function(engine) {

    var PROP_NAME = 'glide.knowman.section.view_roles.draft';
    var BROAD_ROLES = ['itil', 'snc_internal', 'employee', ''];

    var propRec = new GlideRecord('sys_properties');
    propRec.addQuery('name', PROP_NAME);
    propRec.query();

    if (propRec.next()) {
        var val = propRec.getValue('value') || '';
        var roles = val.split(',');
        var broadFound = [];

        for (var i = 0; i < roles.length; i++) {
            var role = roles[i].trim().toLowerCase();
            if (BROAD_ROLES.indexOf(role) >= 0) {
                broadFound.push(role || '(empty)');
            }
        }

        if (broadFound.length > 0 || val === '') {
            engine.finding.setCurrentSource(propRec);
            engine.finding.setValue('finding_details',
                'Property "' + PROP_NAME + '" contains overly permissive role(s): ' +
                broadFound.join(', ') + '. Draft articles may be visible to a wide audience ' +
                'before editorial review. Restrict to knowledge management roles ' +
                '(e.g., "knowledge" or "knowledge_admin").');
            engine.finding.increment();
        }
    }

})(engine);

/**
 * Instance Scan Check: KB Service Portal widgets marked as public
 * Check ID: cstaces-11o
 *
 * Type:     Script Only
 * Category: KB Security — Public Access
 * Severity: High
 *
 * Checks for Service Portal widget instances related to Knowledge Base
 * where the public flag is enabled, allowing unauthenticated access.
 * AppOmni showed attackers can brute-force KB article IDs (KB0000001,
 * KB0000002, etc.) via public KB Article Page widgets.
 *
 * Reference: https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/
 */

(function(engine) {

    // Check sp_widget for public KB widgets
    var KB_WIDGET_NAMES = [
        'KB Article Page', 'KB View 2', 'KB Search', 'KB Category Page',
        'Knowledge Base', 'Knowledge Article View'
    ];

    var widgetRec = new GlideRecord('sp_widget');
    widgetRec.addQuery('name', 'IN', KB_WIDGET_NAMES.join(','));
    widgetRec.addQuery('public', true);
    widgetRec.query();

    while (widgetRec.next()) {
        engine.finding.setCurrentSource(widgetRec);
        engine.finding.setValue('finding_details',
            'Service Portal widget "' + widgetRec.getValue('name') + '" is marked as public. ' +
            'Unauthenticated users can access KB content through this widget. ' +
            'Attackers can brute-force KB article numbers (KB0000001, KB0000002, etc.) ' +
            'to enumerate and extract articles. Uncheck the "Public" flag unless ' +
            'public KB access is intentionally required.');
        engine.finding.increment();
    }

})(engine);

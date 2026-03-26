/**
 * Instance Scan Check: Knowledge Management REST API allows unauthenticated access
 * Check ID: cstaces-11p
 *
 * Type:     Script Only
 * Category: KB Security — API Access
 * Severity: Critical
 *
 * Checks whether the sn_km_api (Knowledge Management REST API) is configured
 * to require authentication. By default, this API is public and does not
 * require authentication — any publicly accessible KB can be queried
 * programmatically without credentials.
 *
 * Reference: https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0959663
 */

(function(engine) {

    var apiRec = new GlideRecord('sys_ws_definition');
    apiRec.addQuery('name', 'CONTAINS', 'Knowledge Management');
    apiRec.addOrCondition('service_address', 'CONTAINS', 'sn_km_api');
    apiRec.query();

    while (apiRec.next()) {
        if (apiRec.getValue('requires_authentication') !== 'true') {
            engine.finding.setCurrentSource(apiRec);
            engine.finding.setValue('finding_details',
                'Scripted REST API "' + apiRec.getValue('name') + '" (' +
                apiRec.getValue('service_address') + ') does not require authentication. ' +
                'Any publicly accessible KB articles can be queried and downloaded via this API ' +
                'without credentials. Enable "Requires Authentication" on this REST API definition. ' +
                'See KB0959663 for guidance.');
            engine.finding.increment();
        }
    }

})(engine);

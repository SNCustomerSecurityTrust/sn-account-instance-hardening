/**
 * Query 3-2: Recent Impersonation Activity
 *
 * Purpose:
 * Identifies whether impersonation capability is actively being used on the
 * instance and by whom. Establishes a behavioral baseline that can be used
 * to detect anomalous activity.
 *
 * What it checks:
 * Queries the syslog table filtered on the Impersonate source for the last
 * 30 days. Parses the message field to extract:
 *   - Who performed the impersonation (from start events only)
 *   - Who was impersonated
 *   - Whether the event was a session start or end
 * Provides session start count and unique impersonator count.
 *
 * Known false positive patterns:
 * Impersonator identity is only available in start events via the by: clause
 * in the message. End events do not include the impersonator - correlate by
 * timestamp to the corresponding start event if attribution is needed.
 *
 * Tables queried: syslog
 * Lookback window: 30 days (configurable via gs.daysAgo)
 * Result limit: 100 (configurable via setLimit)
 */

var gr = new GlideRecord('syslog');
gr.addQuery('source', 'Impersonate');
gr.addQuery('sys_created_on', '>', gs.daysAgo(30));
gr.orderByDesc('sys_created_on');
gr.setLimit(100);
gr.query();

var impersonationEvents = [];
while (gr.next()) {
    var message = gr.message.toString();

    var eventType = '';
    if (message.indexOf('Impersonation start') > -1) {
        eventType = 'start';
    } else if (message.indexOf('Impersonation end') > -1) {
        eventType = 'end';
    }

    var impersonatedUser = '';
    var parenStart = message.indexOf('(');
    var parenEnd = message.indexOf(')');
    if (parenStart > -1 && parenEnd > -1) {
        impersonatedUser = message.substring(parenStart + 1, parenEnd);
    }

    var impersonatedBy = '';
    var byIndex = message.indexOf(' by: ');
    if (byIndex > -1) {
        var byClause = message.substring(byIndex + 5);
        var byParenStart = byClause.indexOf('(');
        if (byParenStart > -1) {
            impersonatedBy = byClause.substring(0, byParenStart).trim();
        }
    }

    impersonationEvents.push({
        timestamp: gr.sys_created_on.toString(),
        event_type: eventType,
        impersonated_user: impersonatedUser,
        impersonated_by: impersonatedBy || 'N/A - end event',
        message: message
    });
}

var startEvents = impersonationEvents.filter(function(e) { return e.event_type === 'start'; });
var uniqueImpersonators = {};
for (var i = 0; i < startEvents.length; i++) {
    if (startEvents[i].impersonated_by !== 'N/A - end event') {
        uniqueImpersonators[startEvents[i].impersonated_by] = true;
    }
}

gs.info('Recent impersonation events (last 30 days): ' + impersonationEvents.length);
gs.info('Session starts: ' + startEvents.length);
gs.info('Unique impersonators: ' + Object.keys(uniqueImpersonators).length);
gs.info(JSON.stringify(impersonationEvents, null, 2));
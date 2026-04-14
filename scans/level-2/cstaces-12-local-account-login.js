(function(engine) {

var seen = {};


var loginHistory = new GlideRecord('sys_user_login_history');
loginHistory.addQuery('authentication_method_used', 'DB');
loginHistory.addEncodedQuery('sys_created_onONLast 30 days@javascript:gs.beginningOfLast30Days()@javascript:gs.endOfLast30Days()');
loginHistory.query();

while (loginHistory.next()) {
  
    var userSysId = loginHistory.getValue('user');
    if (!userSysId) continue;

    // Deduplicate — report each user once with their most recent login
    if (seen[userSysId]) continue;

    var userRec = new GlideRecord('sys_user');
    if (!userRec.get(userSysId)) continue;

    // Only flag users whose record lives in the base sys_user table
    var className = userRec.getValue('sys_class_name');
    if (className && className !== 'sys_user') continue;

    // Skip inactive users — only care about active accounts still logging in locally
    if (userRec.getValue('active') != '1') continue;

	// If we get this far, log user to the dedupe object and proceed to flag finding.
    seen[userSysId] = true;

    var loginTime = loginHistory.getValue('login_time');
    var userName = userRec.getValue('user_name');
    var displayName = userRec.getValue('name');

    engine.finding.setCurrentSource(userRec);
    engine.finding.setValue('finding_details', 'Locally DB login at: ' + loginTime);
    engine.finding.increment();
}

})(engine);

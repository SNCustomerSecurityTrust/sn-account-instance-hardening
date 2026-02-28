//Q5 Web Service Access (REST/ SOAP) Admin Roles

// Find integration users with overly broad access
var gr = new GlideRecord('sys_user');
gr.addQuery('web_service_access_only', 'true');
gr.addQuery('active', 'true');
gr.query();

var integrationUsers = [];
while (gr.next()) {
    var roles = [];
    var roleGR = new GlideRecord('sys_user_has_role');
    roleGR.addQuery('user', gr.sys_id);
    roleGR.query();
    
    while (roleGR.next()) {
        roles.push(roleGR.role.name.toString());
    }
    
    // Flag if integration user has admin roles
    // FIXED: Replace .some() with traditional loop
    var hasAdminRole = false;
    for (var i = 0; i < roles.length; i++) {
        if (roles[i].indexOf('admin') > -1) {
            hasAdminRole = true;
            break;
        }
    }
    
    if (hasAdminRole) {
        integrationUsers.push({
            user: gr.user_name.toString(),
            name: gr.name.toString(),
            roles: roles,
            last_login: gr.last_login_time.toString()
        });
    }
}

gs.warn('Integration users with admin roles: ' + JSON.stringify(integrationUsers, null, 2));

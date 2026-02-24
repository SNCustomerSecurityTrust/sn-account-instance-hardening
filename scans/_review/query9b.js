
// Find privileged users without MFA enabled (if using ServiceNow MFA)

var gr = new GlideRecord('sys_user');
gr.addQuery('active', 'true');
gr.query();

var noMFAUsers = [];
while (gr.next()) {
    // Check if user has admin-level roles
    if (gr.hasRole('admin') || gr.hasRole('security_admin')) {
        // Check MFA enrollment
        var mfaGR = new GlideRecord('sys_user_mfa_device');
        mfaGR.addQuery('user', gr.sys_id);
        mfaGR.addQuery('active', 'true');
        mfaGR.query();
        
        if (!mfaGR.hasNext()) {
            noMFAUsers.push({
                user: gr.user_name.toString(),
                name: gr.name.toString(),
                email: gr.email.toString()
            });
        }
    }
}

gs.warn('Admin users without MFA: ' + JSON.stringify(noMFAUsers, null, 2));

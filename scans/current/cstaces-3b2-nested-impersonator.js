(function(engine) {

    // var impersonators = {};

    // function addUser(userSysId, source) {
    //     if (!userSysId) return;
    //     var u = new GlideRecord('sys_user');
    //     if (u.get(userSysId)) {
    //         if (u.getValue('active') != '1') return;
    //         var uname = u.user_name.toString();
    //         if (!impersonators[uname]) {
    //             impersonators[uname] = {
    //                 user: u.name.toString(),
    //                 user_name: uname,
    //                 email: u.email.toString(),
    //                 last_login: u.last_login_time.toString(),
    //                 is_service_account: (uname.indexOf('svc') > -1 ||
    //                     uname.indexOf('service') > -1 ||
    //                     uname.indexOf('integration') > -1 ||
    //                     uname.indexOf('api') > -1) ? true : false,
    //                 sources: []
    //             };
    //         }
    //         if (impersonators[uname].sources.indexOf(source) === -1) {
    //             impersonators[uname].sources.push(source);
    //         }
    //     }
    // }


    // 5. Parent roles containing impersonator as a child role (role hierarchy)
    var childRole = new GlideRecord('sys_user_role_contains');
    childRole.addQuery('contains.name', 'impersonator');
    childRole.query();
    while (childRole.next()) {
        var parentRoleName = childRole.parent.name.toString();
        var parentRoleId = childRole.getValue('parent');

        // var parentUsers = new GlideRecord('sys_user_has_role');
        // parentUsers.addQuery('role', parentRoleId);
        // parentUsers.addQuery('user.active', 'true');
        // parentUsers.query();
        // while (parentUsers.next()) {

        //     var userRec5 = parentUsers.user.getRefRecord();
		engine.finding.setCurrentSource(childRole);
		engine.finding.setValue('finding_details', 'Found with NESTED IMPERSONATOR role assignment');
		engine.finding.increment();

        //     //addUser(parentUsers.getValue('user'), 'inherited_role:' + parentRoleName);

        // }

        var parentGroups = new GlideRecord('sys_group_has_role');
        parentGroups.addQuery('role', parentRoleId);
        parentGroups.query();
        while (parentGroups.next()) {
            var gName = parentGroups.group.name.toString();
            var gMembers = new GlideRecord('sys_user_grmember');
            gMembers.addQuery('group', parentGroups.getValue('group'));
            gMembers.addQuery('user.active', 'true');
            gMembers.query();
            while (gMembers.next()) {

                var userRec6 = gMembers.user.getRefRecord();
                engine.finding.setCurrentSource(userRec6);
				engine.finding.setValue('finding_details', 'Found with GROUP ASSIGNED NESTED role assignment');
                engine.finding.increment();

                //addUser(gMembers.getValue('user'), 'group_inherited_role:' + gName + ':' + parentRoleName);

            }
        }
    }

    // var results = [];
    // for (var uname in impersonators) {
    //     results.push(impersonators[uname]);
    // }

    // var serviceAccounts = results.filter(function(u) {
    //     return u.is_service_account;
    // });
    // var humanAccounts = results.filter(function(u) {
    //     return !u.is_service_account;
    // });

    // gs.info('Total users with impersonation capability: ' + results.length);
    // gs.info('Human accounts: ' + humanAccounts.length);
    // gs.info('Potential service accounts: ' + serviceAccounts.length);
    // gs.info(JSON.stringify(results, null, 2));

})(engine);

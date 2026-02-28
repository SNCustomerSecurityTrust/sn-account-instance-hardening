(function(engine) {

    var secAdminUsers = {};

    function collectUser(userSysId) {
        if (!userSysId) return;
        var u = new GlideRecord('sys_user');
        if (u.get(userSysId) && u.getValue('active') == '1') {
            secAdminUsers[u.user_name.toString()] = u.name.toString();
        }
    }

    var direct = new GlideRecord('sys_user_has_role');
    direct.addQuery('role.name', 'admin');
    direct.addQuery('user.active', 'true');
    direct.addQuery('state', 'active');
    direct.query();
    while (direct.next()) {
        collectUser(direct.getValue('user'));
    }

    var groupRole = new GlideRecord('sys_group_has_role');
    groupRole.addQuery('role.name', 'admin');
    groupRole.query();
    while (groupRole.next()) {
        var member = new GlideRecord('sys_user_grmember');
        member.addQuery('group', groupRole.getValue('group'));
        member.addQuery('user.active', 'true');
        member.query();
        while (member.next()) {
            collectUser(member.getValue('user'));
        }
    }

    var secAdminUsernames = [];
    for (var u in secAdminUsers) {
        secAdminUsernames.push(u);
    }

    //gs.info('admin population: ' + secAdminUsernames.length + ' users');

    var scriptTables = [
        'sys_script', // Business rules
        'sys_script_include', // Script includes
        'sys_ui_action', // UI actions
        'sys_ws_operation', // Web service operations
        'sys_processor' // Processors
    ];

    var scriptChanges = [];

    for (var i = 0; i < secAdminUsernames.length; i++) {
        var uname = secAdminUsernames[i];
        var audit = new GlideRecord('sys_audit');
        audit.addQuery('user', uname);
        audit.addQuery('tablename', 'IN', scriptTables.join(','));
        audit.addQuery('sys_created_on', '>', gs.daysAgo(30)); // Configurable lookback
        audit.orderByDesc('sys_created_on');
        audit.setLimit(100);
        audit.query();

        while (audit.next()) {
            var tableModified = audit.tablename.toString();
            var recordId = audit.documentkey.toString();
            var scriptName = '';
            var isActive = '';

            var scriptRecord = new GlideRecord(tableModified);
            if (scriptRecord.get(recordId)) {
                scriptName = scriptRecord.name.toString();
                isActive = scriptRecord.active.toString();
            }

			var scriptRecordSpecificChanges = {
                timestamp: audit.sys_created_on.toString(),
                changed_by: uname,
                changed_by_display: secAdminUsers[uname],
                table: tableModified,
                script_name: scriptName,
                is_active: isActive,
                field_changed: audit.fieldname.toString(),
                old_value: audit.oldvalue.toString().substring(0, 100),
                new_value: audit.newvalue.toString().substring(0, 100)
            };

            scriptChanges.push(scriptRecordSpecificChanges);

			engine.finding.setCurrentSource(scriptRecord);
			engine.finding.setValue('finding_details',JSON.stringify(scriptRecordSpecificChanges,null,4));
			engine.finding.increment();
			
        }
    }

    var activeScriptChanges = [];
    var inactiveScriptChanges = [];
    for (var k = 0; k < scriptChanges.length; k++) {
        if (scriptChanges[k].is_active === 'true' || scriptChanges[k].is_active === '1') {
            activeScriptChanges.push(scriptChanges[k]);
        } else {
            inactiveScriptChanges.push(scriptChanges[k]);
        }
    }

    // gs.info('Total script changes by security_admin users (last 30 days): ' + scriptChanges.length);
    // gs.info('Changes to active scripts: ' + activeScriptChanges.length);
    // gs.info('Changes to inactive scripts: ' + inactiveScriptChanges.length);
    // gs.info(JSON.stringify(scriptChanges, null, 2));

})(engine);
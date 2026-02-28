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

    //gs.info('security_admin population: ' + secAdminUsernames.length + ' users');

    var encryptionTables = [
        'sys_kmf_crypto_module', // Crypto modules
        'sys_kmf_map', // Key maps (which fields are encrypted)
        'sys_kmf_key', // Encryption keys
        'sys_kmf_key_store', // Key stores
        'sys_kmf_key_store_alias', // Key store aliases
        'sys_kmf_crypto_spec', // Crypto specifications
        'sys_kmf_key_lifecycle', // Key lifecycle policies
        'sys_certificate', // Certificates
        'sys_encryption_context' // Encryption contexts
    ];

    var highRiskTables = ['sys_kmf_map', 'sys_kmf_key', 'sys_kmf_crypto_module'];
    var encryptionChanges = [];

    for (var i = 0; i < secAdminUsernames.length; i++) {
        var uname = secAdminUsernames[i];
        var audit = new GlideRecord('sys_audit');
        audit.addQuery('user', uname);
        audit.addQuery('tablename', 'IN', encryptionTables.join(','));
        audit.addQuery('sys_created_on', '>', gs.daysAgo(30)); // Configurable lookback
        audit.orderByDesc('sys_created_on');
        audit.setLimit(100);
        audit.query();

        while (audit.next()) {
            var tableModified = audit.tablename.toString();
            var recordId = audit.documentkey.toString();
            var recordName = '';

            var encRecord = new GlideRecord(tableModified);
            if (encRecord.get(recordId)) {
                recordName = encRecord.name.toString();
            }

            var fieldChanged = audit.fieldname.toString();
            var oldValue = audit.oldvalue.toString();
            var newValue = audit.newvalue.toString();
            var isDeactivation = (fieldChanged === 'active' && oldValue === '1' && newValue === '0');

            var isHighRisk = false;
            for (var j = 0; j < highRiskTables.length; j++) {
                if (tableModified === highRiskTables[j]) {
                    isHighRisk = true;
                    break;
                }
            }



			var encryptionAuditObj = {
                timestamp: audit.sys_created_on.toString(),
                changed_by: uname,
                changed_by_display: secAdminUsers[uname],
                table: tableModified,
                record_name: recordName,
                field_changed: fieldChanged,
                old_value: oldValue,
                new_value: newValue,
                is_deactivation: isDeactivation,
                is_high_risk_table: isHighRisk
            };

            encryptionChanges.push(encryptionAuditObj);

			engine.finding.setCurrentSource(encRecord);
			engine.finding.setValue('finding_details',JSON.stringify(encryptionAuditObj,null,4));
			engine.finding.increment();

        }
    }

    var deactivations = [];
    var highRiskChanges = [];
    var otherChanges = [];

    for (var k = 0; k < encryptionChanges.length; k++) {
        if (encryptionChanges[k].is_deactivation) {
            deactivations.push(encryptionChanges[k]);
        } else if (encryptionChanges[k].is_high_risk_table) {
            highRiskChanges.push(encryptionChanges[k]);
        } else {
            otherChanges.push(encryptionChanges[k]);
        }
    }

    gs.info('Total encryption changes by security_admin users (last 30 days): ' + encryptionChanges.length);
    gs.info('Deactivation events: ' + deactivations.length);
    gs.info('High risk table changes (sys_kmf_map, sys_kmf_key, sys_kmf_crypto_module): ' + highRiskChanges.length);
    gs.info('Other encryption changes: ' + otherChanges.length);
    gs.info(JSON.stringify(encryptionChanges, null, 2));

})(engine);
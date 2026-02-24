/**
 * Query 1c: Deprovisioned Users with Privileged Role Assignments (Optional)
 *
 * Purpose:
 * Identifies inactive users who retain privileged role assignments. This is a
 * critical finding because if a deprovisioned account is reactivated for any
 * reason - intentional or accidental - elevated access is immediately restored
 * without requiring a new approval or access request. This is a common gap in
 * offboarding processes where account deactivation and role revocation are
 * treated as separate steps, or where role revocation is skipped entirely.
 *
 * What it checks:
 * - Inactive users with active role assignments for admin, security_admin,
 *   user_admin, delegated_admin, impersonator, itil_admin, catalog_admin,
 *   and knowledge_admin
 * - Separates direct assignments (critical) from inherited assignments (high)
 *   since direct assignments survive reactivation with certainty
 * - Flags users deactivated within the last 90 days as highest reactivation
 *   risk since offboarding processes may still be in progress
 * - Last login timestamp to establish when the account was last active
 * - Locked out status to determine current account state
 *
 * Risk context:
 * Direct role assignments on inactive accounts are a critical finding -
 * reactivation immediately restores full elevated access with no approval gate.
 * Inherited assignments via group membership are high severity - reactivation
 * restores access unless group membership is also removed. Recently deactivated
 * accounts represent the highest reactivation risk as they are most likely to
 * be temporarily reactivated for offboarding tasks or knowledge transfer.
 * Service accounts that have been deactivated but retain privileged roles
 * may indicate an incomplete decommission process.
 *
 * Known limitations:
 * The recently deactivated flag uses sys_updated_on as a proxy for deactivation
 * date since ServiceNow does not store a dedicated deactivation timestamp.
 * sys_updated_on reflects any change to the user record, not just deactivation,
 * so results may include users whose records were recently updated for other
 * reasons. Treat this as an approximation and verify manually where needed.
 *
 * Remediation guidance:
 * All privileged role assignments on inactive accounts should be revoked
 * immediately regardless of how long the account has been inactive. Update
 * offboarding procedures to include explicit role revocation as a required
 * step separate from account deactivation. Consider implementing an automated
 * workflow that revokes privileged roles at the time of deactivation.
 *
 * Tables queried: sys_user_has_role, sys_user
 */

var roleList = [
    'admin',
    'security_admin',
    'user_admin',
    'delegated_admin',
    'impersonator',
    'itil_admin',
    'catalog_admin',
    'knowledge_admin'
];

var gr = new GlideRecord('sys_user_has_role');
gr.addQuery('role.name', 'IN', roleList.join(','));
gr.addQuery('user.active', false);
gr.addQuery('state', 'active');
gr.query();

var direct = [];
var inherited = [];

while (gr.next()) {
    var uname = gr.user.user_name.toString();
    var record = {
        sys_id: gr.getUniqueValue(),
        user_sys_id: gr.getValue('user'),
        user_name: uname,
        user_display_name: gr.user.getDisplayValue(),
        email: gr.user.email.toString(),
        role: gr.role.name.toString(),
        inherited: gr.inherited.toString(),
        sys_created_on: gr.sys_created_on.toString(),
        last_login: gr.user.last_login_time.toString(),
        locked_out: gr.user.locked_out.toString(),
        is_service_account: (uname.indexOf('svc') > -1 ||
                             uname.indexOf('service') > -1 ||
                             uname.indexOf('integration') > -1 ||
                             uname.indexOf('api') > -1) ? true : false
    };

    if (gr.inherited.toString() === 'false') {
        direct.push(record);
    } else {
        inherited.push(record);
    }
}

// Flag recently deactivated users (last 90 days) - highest reactivation risk
// Note: uses sys_updated_on as proxy for deactivation date - see known limitations
var recentlyDeactivated = [];
var allRecords = direct.concat(inherited);

for (var i = 0; i < allRecords.length; i++) {
    var userGR = new GlideRecord('sys_user');
    userGR.get(allRecords[i].user_sys_id);
    var updatedOn = new GlideDateTime(userGR.sys_updated_on.toString());
    var ninetyDaysAgo = new GlideDateTime();
    ninetyDaysAgo.addDaysUTC(-90);
    if (updatedOn.compareTo(ninetyDaysAgo) > 0) {
        recentlyDeactivated.push({
            user_name: allRecords[i].user_name,
            user_display_name: allRecords[i].user_display_name,
            email: allRecords[i].email,
            role: allRecords[i].role,
            inherited: allRecords[i].inherited,
            is_service_account: allRecords[i].is_service_account,
            deactivated_around: userGR.sys_updated_on.toString()
        });
    }
}

var serviceAccounts = allRecords.filter(function(u) { return u.is_service_account; });

gs.info('=== DEPROVISIONED USERS WITH PRIVILEGED ROLES ===');
gs.info('Direct assignments (critical - survives reactivation): ' + direct.length);
gs.info('Inherited assignments (high - survives reactivation): ' + inherited.length);
gs.info('Total records: ' + (direct.length + inherited.length));
gs.info('Recently deactivated (<90 days, highest reactivation risk): ' + recentlyDeactivated.length);
gs.info('Potential service accounts: ' + serviceAccounts.length);
gs.info('\nDirect assignments:');
gs.info(JSON.stringify(direct, null, 2));
gs.info('\nInherited assignments:');
gs.info(JSON.stringify(inherited, null, 2));
gs.info('\nRecently deactivated users:');
gs.info(JSON.stringify(recentlyDeactivated, null, 2));
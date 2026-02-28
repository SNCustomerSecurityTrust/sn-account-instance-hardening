

//Q8 Cross-Domain Access (is a seperation of duties required)
// Check for users with cross-domain access (if domain separation enabled)
if (gs.getProperty('glide.sys.domain_separation.enabled') == 'true') {
    var gr = new GlideRecord('sys_user');
    gr.addQuery('active', 'true');
    gr.addNullQuery('sys_domain'); // Users without domain assignment
    gr.query();
    
    var orphanedUsers = [];
    while (gr.next()) {
        orphanedUsers.push({
            user: gr.user_name.toString(),
            name: gr.name.toString()
        });
    }
    
    gs.warn('Users without domain assignment: ' + 
            JSON.stringify(orphanedUsers, null, 2));
}
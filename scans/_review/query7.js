//Q7- UI Policy & Client Script Input Validation (mandatory field bypass)
var gr = new GlideRecord('sys_ui_policy');
gr.addQuery('active', 'true');
gr.query();

while (gr.next()) {
    var actions = new GlideRecord('sys_ui_policy_action');
    actions.addQuery('ui_policy', gr.sys_id);
    actions.addQuery('mandatory', 'false');
    actions.query();
    
    if (actions.hasNext()) {
        gs.info('UI Policy bypassing mandatory fields: ' + 
                gr.short_description.toString());
    }
}
// Review IP access control rules
var gr = new GlideRecord('sys_security_acl_ip');
gr.addQuery('active', 'true');
gr.orderBy('order');
gr.query();

var ipRules = [];
while (gr.next()) {
    ipRules.push({
        type: gr.type.toString(),
        ip_address: gr.ip_address.toString(),
        ip_mask: gr.ip_mask.toString(),
        active: gr.active.toString(),
        order: gr.order.toString()
    });
}

gs.info('IP Access Control rules: ' + JSON.stringify(ipRules, null, 2));

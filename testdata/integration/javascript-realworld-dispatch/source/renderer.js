const _ = require('lodash');
function renderTemplate(tmpl, data) {
    return _.template(tmpl)(data);
}
module.exports = { renderTemplate };

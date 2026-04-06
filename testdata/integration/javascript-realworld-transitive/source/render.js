const _ = require('lodash');

function renderTemplate(tmpl, data) {
    const compiled = _.template(tmpl);
    return compiled(data);
}

module.exports = { renderTemplate };

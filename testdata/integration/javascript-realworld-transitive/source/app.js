const _ = require('lodash');
const render = require('./render');

const result = render.renderTemplate('<%= name %>', { name: 'World' });
console.log(result);

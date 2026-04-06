const _ = require('lodash');
const app = require('../app');
// Test that uses lodash utilities but NOT the vulnerable template function
const result = _.isString('hello');
console.log('isString test:', result);

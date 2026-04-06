const express = require('express');
const _ = require('lodash');
const app = express();
app.get('/users', (req, res) => {
    const users = [{name: 'Alice'}, {name: 'Bob'}];
    res.json(_.map(users, 'name'));
});
app.listen(3000);

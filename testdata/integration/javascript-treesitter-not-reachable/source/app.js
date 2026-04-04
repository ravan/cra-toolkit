const express = require('express');
const _ = require('lodash');
const app = express();

app.get('/users', (req, res) => {
    const users = [{ name: 'Alice' }, { name: 'Bob' }];
    const names = _.map(users, 'name');
    res.json(names);
});

app.listen(3000);

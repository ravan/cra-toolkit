const express = require('express');
const _ = require('lodash');
const app = express();
app.post('/config', (req, res) => {
    const defaults = { theme: 'light', lang: 'en' };
    const config = _.merge(defaults, req.body);
    res.json({ setting: _.get(config, 'theme') });
});
app.listen(3000);

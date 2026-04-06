const express = require('express');
const _ = require('lodash');
const app = express();

const renderers = {
    template: function(tmpl, data) {
        return _.template(tmpl)(data);
    }
};

function dispatch(type, tmpl, data) {
    return renderers[type](tmpl, data);
}

app.post('/render', (req, res) => {
    res.send(dispatch('template', req.body.template, req.body.data));
});
app.listen(3000);

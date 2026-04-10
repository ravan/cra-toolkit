// This app imports axios but configures it to never follow redirects, so
// follow-redirects' vulnerable path is not reached.

const axios = require('axios');

async function fetchNoRedirects(url) {
    const response = await axios.get(url, { maxRedirects: 0 });
    return response.data;
}

module.exports = { fetchNoRedirects };

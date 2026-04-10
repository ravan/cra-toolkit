// Express app that uses axios to fetch URLs. The transitive dep follow-redirects
// is invoked by axios for every redirect response, reaching CVE-2022-0155's
// credential-leak code path.

const axios = require('axios');

async function fetchWithRedirects(url) {
    const response = await axios.get(url, { maxRedirects: 5 });
    return response.data;
}

module.exports = { fetchWithRedirects };

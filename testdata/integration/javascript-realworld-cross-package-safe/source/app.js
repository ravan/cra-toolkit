// App that accepts JSON bodies only.
// body-parser.json() uses JSON.parse internally — qs is never called.
// CVE-2022-24999 in qs@6.7.0 is not reachable from this code path.

const bodyParser = require('body-parser')

const parseJson = bodyParser.json()

function handleJsonPost(req, res, next) {
  parseJson(req, res, next)
}

module.exports = { handleJsonPost }

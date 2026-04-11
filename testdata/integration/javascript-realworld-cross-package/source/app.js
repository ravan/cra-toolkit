// App that processes URL-encoded form bodies.
// body-parser.urlencoded({ extended: true }) internally calls qs.parse,
// reaching CVE-2022-24999 (prototype pollution in qs < 6.10.3).

const bodyParser = require('body-parser')

const parseUrlEncoded = bodyParser.urlencoded({ extended: true })

function handleFormSubmit(req, res, next) {
  parseUrlEncoded(req, res, next)
}

module.exports = { handleFormSubmit }

const debug = require('debug')('prismarine-auth')
const crypto = require('crypto')

async function checkStatus (res) {
  if (res.ok) {
    return res.json()
  } else {
    const resp = await res.text()
    const url = res.url || ''
    debug('Request fail', url, resp)
    throw Error(`${res.status} ${res.statusText} url=${url} ${resp}`)
  }
}

function checkStatusWithHelp (errorDict) {
  return async function (res) {
    if (res.ok) return res.json()
    const resp = await res.text()
    const url = res.url || ''
    debug('Request fail', url, resp)
    throw new Error(`${res.status} ${res.statusText} url=${url} ${resp} ${errorDict[res.status] ?? ''}`)
  }
}

function createHash (input) {
  return crypto.createHash('sha1')
    .update(input ?? '', 'binary')
    .digest('hex').substr(0, 6)
}

function nextUUID () {
  return globalThis.crypto.randomUUID()
}

module.exports = { checkStatus, checkStatusWithHelp, createHash, nextUUID }

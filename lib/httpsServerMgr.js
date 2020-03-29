'use strict'
const
    https = require('https'),
    {
        createSecureContext
    } = require('tls'),
    color = require('colorful'),
    certMgr = require('./certMgr'),
    logUtil = require('./log'),
    {
        getFreePort,
        isIpDomain,
    } = require('./util'),
    wsServerMgr = require('./wsServerMgr'),
    {
        SSL_OP_NO_SSLv3,
        SSL_OP_NO_TLSv1,
    } = require('constants')
    ;
// dependencies removed:
    // async = require('async'),
    // co = require('co'),
    // asyncTask = require('async-task-mgr');
    // crypto = require('crypto'),

function NOOP(){}

// IMPORTANT: looks like anyproxy had a bug ==> constants.SSL_OP_NO_SSLv3 || constants.SSL_OP_NO_TLSv1,
const secureOptions = SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;

// using sni to avoid multiple ports
function sni_prepare_cert(serverName, cb) {
    certMgr.getCertificate(serverName, function (err, key, cert) {
        if (err)
            _sni_prepare_cert_on_err(err);
        else {
            try {
                const ctx = createSecureContext({
                    key,
                    cert,
                });
                cb(null, ctx);
                _sni_prepare_cert_on_done(serverName);
            }
            catch(err) {
                _sni_prepare_cert_on_err(err);
            }
        }
    });
}
function _sni_prepare_cert_on_done(serverName) {
}
    // TODO:
    // logUtil.printLog(color.yellow(color.bold('[internal https]')) + color.yellow(
    //     `proxy server for ${serverName} established`
    // ));

function _sni_prepare_cert_on_err(err) {
    logUtil.printLog('err occurred when prepare certs for SNI - ' + err, logUtil.T_ERR);
    logUtil.printLog('err occurred when prepare certs for SNI - ' + err.stack, logUtil.T_ERR);
}


let _https_ip = '';
let _https_port = 0;
let _https_handler = NOOP;

/**
 * Create an https server
 *
 * @param {number} port
 * @param {function} handler
 */
function createHttpsServer(port,handler) {
    if (!port || !handler)
        throw new Error('createHttpsServer requires port & handler');
    _https_port = port;
    _https_handler = handler;
    return new Promise(_createHttpsServer_promise);
}
function _createHttpsServer_promise(resolve) {
    const port = _https_port
    const handler = _https_handler;
    _https_handler = NOOP;
    certMgr.getCertificate('anyproxy_internal_https_server', function (err, key, cert) {
        const server = https.createServer(
            {
                key,
                cert,
                secureOptions,
                SNICallback: sni_prepare_cert,
            },
            handler
        ).listen(port);
        resolve(server);
    });
}

/**
* create an https server that serving on IP address
* @param @required {string} ip the IP address of the server
* @param @required {number} port the port to listen on
* @param @required {function} handler the handler of each connect
*/
function createIPHttpsServer(ip, port, handler) {
    if (!ip || !port || !handler)
        throw new Error('createIPHttpsServer requires ip, port, handler');
    _https_ip = ip;
    _https_port = port;
    _https_handler = handler;
    return new Promise(_createIPHttpsServer_promise);
}
function _createIPHttpsServer_promise(resolve) {
    const port = _https_port
    const handler = _https_handler;
    _https_handler = NOOP;
    certMgr.getCertificate(_https_ip, function (err, key, cert) {
        const server = https.createServer(
            {
                key,
                cert,
                secureOptions,
            },
            handler
        ).listen(port);
        resolve(server);
    });
}

/**
 *
 *
 * @class httpsServerMgr
 * @param {object} config
 * @param {function} config.handler handler to deal https request
 *
 */
class httpsServerMgr {
    constructor(config) {
        if (!config || !config.handler) {
            throw new Error('handler is required');
        }
        const default_host = '0.0.0.0';
        // this.httpsAsyncTask = new asyncTask();
        const {handler, wsHandler} = config;
        const server_promises = new Map();
        this.handler = handler;
        this.wsHandler = wsHandler
        this.getSharedHttpsServer = async function(hostname) {
            // ip address will have a unique name
            const host = isIpDomain(hostname) ? hostname : default_host;
            return server_promises.has(host)
                ? await server_promises.get(host)
                : await register_server(host, hostname)
            ;
        }
        function register_server(host, hostname) {
            const promise = _register_server(host, hostname, 0);
            server_promises.set(host, promise);
            return promise;
        }

        // TODO: global.proxy_default_port
        const {proxy_default_port} = global;
        async function get_port(host) {
            if (host === default_host && proxy_default_port)
                return proxy_default_port;
            return await getFreePort();
        }
        async function _register_server(host, hostname, tries) {
            try {
                const port = await get_port(host);
                const server = isIpDomain(hostname)
                    ? await createIPHttpsServer(
                        hostname,
                        port,
                        handler
                    )
                    : await createHttpsServer(
                        port,
                        handler
                    )
                    ;
                // console.log('\n\n',{host,port,hostname},process.pid,'\n\n')
                // server.on('upgrade', _server_on_upgrade);
                wsServerMgr.getWsServer({
                    server,
                    connHandler: wsHandler
                });
                return {
                    host,
                    port,
                };
            }
            catch (e) {
                if (tries === 0)
                    return await _register_server(host, hostname, ++tries)
                else
                    return {
                        host: null,
                        port: null
                    }
            }
        }
        // function _server_on_upgrade(req, cltSocket, head) {
        //     logUtil.debug('will let WebSocket server to handle the upgrade event');
        // }
    }
}

module.exports = httpsServerMgr;

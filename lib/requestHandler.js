'use strict';

const http = require('http'),
    https = require('https'),
    net = require('net'),
    url_parse = require('url').parse,
    color = require('colorful'),
    Buffer = require('buffer').Buffer,
    util = require('./util'),
    Stream = require('stream'),
    logUtil = require('./log'),
    HttpsServerMgr = require('./httpsServerMgr'),
    Readable = require('stream').Readable;

// to fix issue with TLS cache, refer to: https://github.com/nodejs/node/issues/8368
// https.globalAgent.maxCachedSessions = 0;

const agent_opts = {
    keepAlive: true,
    keepAliveMsecs: 1500,
    // timeout: 60000, // ? https://nodejs.org/dist/latest-v12.x/docs/api/net.html#net_socket_settimeout_timeout_callback
    // maxFreeSockets: 1024
};
const http_request = http.request;
const http_default_agent = new http.Agent(agent_opts); // http.globalAgent
const https_request = https.request;
const https_default_agent = new https.Agent(agent_opts);
// Stop Wasting Connections, Use HTTP Keep-Alive https://lob.com/blog/use-http-keep-alive

// https://github.com/aws-amplify/amplify-js/issues/2959
// connection reset when using https server/client combi without keepalive #23128 https://github.com/nodejs/node/issues/23128
// https://github.com/nodejs/node/issues/28438
// TODO:
//      ? https://github.com/MicrosoftDocs/azure-docs/issues/29600
//      * http: add reusedSocket property on client request https://github.com/nodejs/node/pull/29715
//          https://bigcodenerd.org/retrying-failed-http-requests-node-js/
// TLSWrap objects grow with HTTP keep-alive enabled until out memory error occurs #33468
//      https://github.com/nodejs/node/issues/33468
//      node v13 bugs with keepAlive..
// future versions TODOs
//      * http: added scheduling option to http agent (#33278) https://github.com/nodejs/node/pull/33278

// options.agent = keepAliveAgent;
// http.request(options, onResponseCallback);

// ???? REMOVE ???? proxyReq.useChunkedEncodingByDefault = true;
// https://nodejs.org/dist/latest-v12.x/docs/api/http.html#http_request_reusedsocket
const REQUEST_BY_PROTOCOL = {
    "http": function(o, cb, errcb, reqData) {
        if (o.agent === undefined)
            o.agent = http_default_agent
        return http_request(o, cb)
            .on('error',errcb)
            .end(reqData)
        ;
    },
    "https": function(o, cb, errcb, reqData) {
        if (o.agent === undefined)
            o.agent = https_default_agent
        return https_request(o, cb)
            .on('error',errcb)
            .end(reqData)
        ;
    }
}
const RETRY_THRESHOLD = 3;
// Solves the "keep-alive-race" https://code-examples.net/en/q/28a8069
function proxy_request(protocol, o, cb, reject, reqData, retry_count) {
    const req = REQUEST_BY_PROTOCOL[protocol](
        o, cb,
        function(err) {
            if (req.reusedSocket
                && err.code === 'ECONNRESET'
                && retry_count++ < RETRY_THRESHOLD
            )
                proxy_request(protocol, o, cb, reject, reqData, retry_count)
            else
                reject(err);
        },
        reqData
    );

}

const DEFAULT_CHUNK_COLLECT_THRESHOLD = 20 * 1024 * 1024; // about 20 mb
const DEFAULT_READABLE_CONF = {
    highWaterMark: DEFAULT_CHUNK_COLLECT_THRESHOLD * 5
};

class CommonReadableStream extends Readable {
    constructor(config) {
        super(DEFAULT_READABLE_CONF);
    }
    _read(size) {

    }
}

/*
* get error response for exception scenarios
*/
let getErrorResponse = function (error, fullUrl) {
    const requestErrorHandler = require('./requestErrorHandler');
    getErrorResponse = function (error, fullUrl) {
        // default error response
        const errorResponse = {
            statusCode: 500,
            header: {
                'Content-Type': 'text/html; charset=utf-8',
                'Proxy-Error': true,
                'Proxy-Error-Message': error ? JSON.stringify(error) : 'null'
            },
            body: requestErrorHandler.getErrorContent(error, fullUrl)
        };

        return errorResponse;
    }
    return getErrorResponse(error, fullUrl);
}

/**
 * fetch remote response
 *
 * @param {string} protocol
 * @param {object} options options of http.request
 * @param {buffer} reqData request body
 * @param {object} config
 * @param {boolean} config.dangerouslyIgnoreUnauthorized
 * @param {boolean} config.chunkSizeThreshold
 * @returns
 */
let _protocol;
let _options;
let _reqData;
let _config;
function fetchRemoteResponse(protocol, options, reqData, config) {

    if (!config.chunkSizeThreshold)
        throw new Error('chunkSizeThreshold is required');

    const {headers} = options;
    delete headers['content-length']; // will reset the content-length after rule
    delete headers['Content-Length'];
    delete headers['Transfer-Encoding'];
    delete headers['transfer-encoding'];

    options.rejectUnauthorized = !config.dangerouslyIgnoreUnauthorized;
    // if (config.dangerouslyIgnoreUnauthorized) {
    //     options.rejectUnauthorized = false;
    // }

    _protocol = protocol;
    _options = options;
    _reqData = reqData || '';
    _config = config;
    return new Promise(fetch_promise_ctor);
}



function fetch_promise_ctor(resolve, reject) {

    var protocol = _protocol;
    var options = _options;
    var reqData = _reqData;
    var config = _config;

    proxy_request(protocol, options, _request_cb, reject, reqData, 0)

    function _request_cb (res) {
        // var config = _config;
        res.headers = util.getHeaderFromRawHeaders(res.rawHeaders);
        //deal response header
        const statusCode = res.statusCode;
        const resHeader = res.headers;
        let resDataChunks = []; // array of data chunks or stream
        const rawResChunks = []; // the original response chunks
        let resDataStream = null;
        let resSize = 0;
        const finishCollecting = function () {
            new Promise( function (fulfill, rejectParsing) {
                if (resDataStream) {
                    fulfill(resDataStream);
                } else {
                    const serverResData = Buffer.concat(resDataChunks);
                    const originContentLen = Buffer.byteLength(serverResData);
                    // remove gzip related header, and ungzip the content
                    // note there are other compression types like deflate
                    const contentEncoding = resHeader['content-encoding'] || resHeader['Content-Encoding'];

                    // only do unzip when there is res data
                    if (!originContentLen) {
                        fulfill(serverResData);
                    }
                    else if (/gzip/i.test(contentEncoding)) {
                        _res_encoding_header(resHeader, contentEncoding, originContentLen);
                        _res_gunzip(serverResData, fulfill, rejectParsing);
                    }
                    else if (/deflate/i.test(contentEncoding)) {
                        _res_encoding_header(resHeader, contentEncoding, originContentLen);
                        _res_inflate_raw(serverResData, fulfill, rejectParsing);
                    }
                    else if (/br/i.test(contentEncoding)) {
                        _res_encoding_header(resHeader, contentEncoding, originContentLen);
                        _res_unbrotli(serverResData, fulfill, rejectParsing);
                    }
                    else
                        fulfill(serverResData);
                }
            }).then(function (serverResData) {
                resolve({
                    statusCode,
                    header: resHeader,
                    body: serverResData,
                    rawBody: rawResChunks,
                    _res: res,
                });
            }).catch(reject);
        };

        //deal response data
        res.on('data', function (chunk) {
            rawResChunks.push(chunk);
            if (resDataStream) { // stream mode
                resDataStream.push(chunk);
            } else { // dataChunks
                resSize += chunk.length;
                resDataChunks.push(chunk);

                // stop collecting, convert to stream mode
                if (resSize >= config.chunkSizeThreshold) {
                    resDataStream = new CommonReadableStream();
                    while (resDataChunks.length) {
                        resDataStream.push(resDataChunks.shift());
                    }
                    resDataChunks = null;
                    finishCollecting();
                }
            }
        });

        res.once('end', function () {
            if (resDataStream) {
                resDataStream.push(null); // indicate the stream is end
            } else {
                finishCollecting();
            }
        });
        res.once('error', function (error) {
            logUtil.printLog('error happend in response:' + error, logUtil.T_ERR);
            reject(error);
        });
    }
}


/**
 * when the content is unzipped, update the header content
 * set origin content length into header
 */
function _res_encoding_header(resHeader, contentEncoding, originContentLen) {
    if (contentEncoding) {
        resHeader['x-anyproxy-origin-content-encoding'] = contentEncoding;
        delete resHeader['content-encoding'];
        delete resHeader['Content-Encoding'];
    }
    resHeader['x-anyproxy-origin-content-length'] = originContentLen;
}

function _zlib() {
    const zlib = require('zlib');
    _zlib = function() {
        return zlib;
    }
    return zlib;
}
function _brotliTorb() {
    const brotliTorb = require('brotli');
    _brotliTorb = function() {
        return brotliTorb;
    }
    return brotliTorb;
}


function _res_gunzip(serverResData, fulfill, rejectParsing) {
    _zlib().gunzip(serverResData, function (err, buff) {
        if (err)
            rejectParsing(err);
        else
            fulfill(buff);
    });
}
function _res_inflate_raw(serverResData, fulfill, rejectParsing){
    _zlib().inflateRaw(serverResData, function (err, buff) {
        if (err)
            rejectParsing(err);
        else
            fulfill(buff);
    });
}
function _res_unbrotli(serverResData, fulfill, rejectParsing) {
    try {
        const result = _brotliTorb().decompress(serverResData); // Unit8Array
        fulfill( Buffer.from(result) );
    } catch (e) {
        rejectParsing(e);
    }
}




function _normalize_protocol(encrypted, url) {
    return (encrypted && !(/^http:/).test(url)) ? 'https' : 'http';
}
function _normalize_full_url(encrypted, url) {

}
/**
 * get a request handler for http/https server
 *
 * @param {RequestHandler} reqHandlerCtx
 * @param {object} userRule
 * @param {Recorder} recorder
 * @returns
 */


function getUserReqHandler(userRule, recorder) {
    const reqHandlerCtx = this
    const chunkSizeThreshold = DEFAULT_CHUNK_COLLECT_THRESHOLD;

    async function _fetch_if_needed(req) {
        if (req.response) {
            // user-assigned local response
            return req;
        } else if (req.req_opts) {
            const res = await fetchRemoteResponse(
                req.protocol,
                req.req_opts,
                req.req_data,
                {
                    dangerouslyIgnoreUnauthorized: reqHandlerCtx.dangerouslyIgnoreUnauthorized,
                    chunkSizeThreshold,
                });
            req.response = {
                statusCode: res.statusCode,
                header: res.header,
                body: res.body,
                rawBody: res.rawBody
            }
        } else {
            throw new Error('lost response or req_opts, failed to continue');
        }
    }

    return async function (req, userRes) {
        // console.time('req')
        /*
        note
          req.url is wired
          in http  server: http://www.example.com/a/b/c
          in https server: /a/b/c
        */

        const host = req.headers.host;
        const protocol = _normalize_protocol(Boolean(req.connection.encrypted), req.url);

        // try find fullurl https://github.com/alibaba/anyproxy/issues/419
        // const fullUrl = protocol === 'http' ? req.url : (protocol + '://' + host + req.url);
        let fullUrl = protocol + '://' + host + req.url;
        if (protocol === 'http') {
            const reqUrlPattern = url_parse(req.url);
            if (reqUrlPattern.host && reqUrlPattern.protocol)
                fullUrl = req.url;
        }
        const urlPattern = url_parse(fullUrl);
        const path = urlPattern.path;

        let req_data;
        let requestDetail;

        let resourceInfo = null;
        let resourceInfoId = -1;

        let _record_request = NOOP;
        let _record_reponse = NOOP;
        if (recorder) {
            _record_request = function() {
                resourceInfo = {
                    host,
                    method: req.method,
                    path,
                    protocol,
                    url: protocol + '://' + host + path,
                    req,
                    startTime: new Date().getTime()
                };
                resourceInfoId = recorder.appendRecord(resourceInfo);
                try {
                    resourceInfo.reqBody = req_data.toString(); //TODO: deal reqBody in webInterface.js
                    recorder.updateRecord(resourceInfoId, resourceInfo);
                } catch (e) { }
            }
            _record_reponse = function (responseInfo) {
                resourceInfo.endTime = new Date().getTime();
                resourceInfo.res = { //construct a self-defined res object
                    statusCode: responseInfo.statusCode,
                    headers: responseInfo.header,
                };

                resourceInfo.statusCode = responseInfo.statusCode;
                resourceInfo.resHeader = responseInfo.header;
                resourceInfo.resBody = responseInfo.body instanceof CommonReadableStream ? '(big stream)' : (responseInfo.body || '');
                resourceInfo.length = resourceInfo.resBody.length;
                // console.info('===> resbody in record', resourceInfo);
                recorder.updateRecord(resourceInfoId, resourceInfo);
            }
        }
        // refer to https://github.com/alibaba/anyproxy/issues/103
        // construct the original headers as the reqheaders
        req.headers = util.getHeaderFromRawHeaders(req.rawHeaders);

        logUtil.printLog(color.green(`received request to: ${req.method} ${host}${path}`));

        /**
         * fetch complete req data
         */
        const fetch_promise = new Promise(_fetch_req_data_promise);
        function _fetch_req_data_promise(resolve) {
            const _fetch_post_data = [];
            req.on('data', function _fetch_on_data(chunk) {
                _fetch_post_data.push(chunk);
            });
            req.on('end', function () {
                req_data = Buffer.concat(_fetch_post_data);
                _fetch_post_data.length = 0;
                resolve();
            });
        }


        /**
         * prepare detailed request info
         */
        const prepareRequestDetail = function () {
            requestDetail = {
                protocol,
                url: fullUrl,
                req_opts: {
                    agent: undefined,
                    hostname: urlPattern.hostname || req.headers.host,
                    port: urlPattern.port || req.port || (/https/.test(protocol) ? 443 : 80),
                    path,
                    method: req.method,
                    headers: req.headers
                },
                req_data,
                response: null,
                _req: req,
            };
            // return Promise.resolve();
        };


        // fetch complete request data
        try {
            await fetch_promise;
            prepareRequestDetail()
            _record_request();
            await userRule.beforeSendRequest(
                requestDetail,
                _fetch_if_needed);
        }
        catch(error) {
            console.error(error)
            requestDetail = await _fetch_catch(error);
        }

        const response = requestDetail.response;
        if (!response)
            _fetch_response_catch(new Error('failed to get response info'));
        else if (!response.statusCode)
            _fetch_response_catch(new Error('failed to get response status code'));
        else if (!response.header)
            _fetch_response_catch(new Error('filed to get response header'))
        else {
            try {
                _record_reponse(
                    sendFinalResponse( response ) );
            }
            catch(error) {
                _fetch_response_catch(error);
            }
        }

        async function _fetch_catch(error) {
            logUtil.printLog(util.collectErrorLog(error), logUtil.T_ERR);

            let errorResponse = getErrorResponse(error, fullUrl);

            try { // call user rule
                const userResponse = await userRule.onError(Object.assign({}, requestDetail), error);
                if (userResponse && userResponse.response && userResponse.response.header) {
                    errorResponse = userResponse.response;
                }
            } catch (e) { }

            return {
                response: errorResponse
            };
        }

        function _fetch_response_catch(error) {
            logUtil.printLog(color.green('Send final response failed:' + error.message), logUtil.T_ERR);
        }


        // send response to client
        function sendFinalResponse (responseInfo) {

            const resHeader = responseInfo.header;
            const responseBody = responseInfo.body || '';

            const transferEncoding = resHeader['transfer-encoding'] || resHeader['Transfer-Encoding'] || '';
            const contentLength = resHeader['content-length'] || resHeader['Content-Length'];
            const connection = resHeader.Connection || resHeader.connection;
            if (contentLength) {
                delete resHeader['content-length'];
                delete resHeader['Content-Length'];
            }

            // set proxy-connection
            if (connection) {
                resHeader['x-anyproxy-origin-connection'] = connection;
                delete resHeader.connection;
                delete resHeader.Connection;
            }

            // if there is no transfer-encoding, set the content-length
            if (!global._throttle
                && transferEncoding !== 'chunked'
                && !(responseBody instanceof CommonReadableStream)
            ) {
                resHeader['Content-Length'] = util.getByteSize(responseBody);
            }

            userRes.writeHead(responseInfo.statusCode, resHeader);

            if (global._throttle) {
                if (responseBody instanceof CommonReadableStream) {
                    responseBody.pipe(global._throttle.throttle()).pipe(userRes);
                } else {
                    const thrStream = new Stream();
                    thrStream.pipe(global._throttle.throttle()).pipe(userRes);
                    thrStream.emit('data', responseBody);
                    thrStream.emit('end');
                }
            } else {
                if (responseBody instanceof CommonReadableStream) {
                    responseBody.pipe(userRes);
                } else {
                    userRes.end(responseBody);
                }
            }
            // console.timeEnd('req')
            return responseInfo;
        }
    }
}

// /**
//  * get a handler for CONNECT request
//  *
//  * @param {RequestHandler} reqHandlerCtx
//  * @param {object} userRule
//  * @param {Recorder} recorder
//  * @param {object} httpsServerMgr
//  * @returns
//  */
// function getConnectReqHandler(reqHandlerCtx, userRule, recorder, httpsServerMgr) {

//     return
// }

/**
* get a websocket event handler
  @param @required {object} wsClient
*/
function getWsHandler(userRule, recorder, wsClient, wsReq) {
    const self = this;
    const WebSocket = require('ws');
    try {
        let resourceInfoId = -1;
        const resourceInfo = {
            wsMessages: [] // all ws messages go through AnyProxy
        };
        const clientMsgQueue = [];
        const serverInfo = getWsReqInfo(wsReq);
        const serverInfoPort = serverInfo.port ? `:${serverInfo.port}` : '';
        const wsUrl = `${serverInfo.protocol}://${serverInfo.hostName}${serverInfoPort}${serverInfo.path}`;
        // console.log({
        //     headers: serverInfo.noWsHeaders,
        // })
        const proxyWs = new WebSocket(wsUrl,
            ['xmpp'],
            {
                rejectUnauthorized: true,// !self.dangerouslyIgnoreUnauthorized,
                headers: serverInfo.noWsHeaders,

                // TODO: ???
                followRedirects:true,
                perMessageDeflate: true,
            });

        if (recorder) {
            Object.assign(resourceInfo, {
                host: serverInfo.hostName,
                method: 'WebSocket',
                path: serverInfo.path,
                url: wsUrl,
                req: wsReq,
                startTime: new Date().getTime()
            });
            resourceInfoId = recorder.appendRecord(resourceInfo);
        }

        /**
        * store the messages before the proxy ws is ready
        */
        const sendProxyMessage = function (event) {
            const message = event.data;
            //console.log(proxyWs.readyState,{message})
            // process.exit(0)
            if (proxyWs.readyState === 1) {
                // if there still are msg queue consuming, keep it going
                if (clientMsgQueue.length > 0)
                    clientMsgQueue.push(message);
                else
                    proxyWs.send(message);
            } else {
                clientMsgQueue.push(message);
            }
        }

        /**
        * When the source ws is closed, we need to close the target websocket.
        * If the source ws is normally closed, that is, the code is reserved, we need to transfrom them
        */
        const getCloseFromOriginEvent = function (event) {
            const code = event.code || '';
            const reason = event.reason || '';
            let targetCode = '';
            let targetReason = '';
            if (code >= 1004 && code <= 1006) {
                targetCode = 1000; // normal closure
                targetReason = `Normally closed. The origin ws is closed at code: ${code} and reason: ${reason}`;
            } else {
                targetCode = code;
                targetReason = reason;
            }
            return {
                code: targetCode,
                reason: targetReason
            }
        }

        /**
        * consruct a message Record from message event
        * @param @required {event} messageEvent the event from websockt.onmessage
        * @param @required {boolean} isToServer whether the message is to or from server
        *
        */
        const recordMessage = (recorder)
            ? function (messageEvent, isToServer) {
                const message = {
                    time: Date.now(),
                    message: messageEvent.data,
                    isToServer: isToServer
                };

                // resourceInfo.wsMessages.push(message);
                recorder.updateRecordWsMessage(resourceInfoId, message);
            }
            : function(msg,is2server) {}

        // this event is fired when the connection is build and headers is returned
        if (recorder) {
            proxyWs.on('upgrade', function (response) {
                resourceInfo.endTime = new Date().getTime();
                const headers = response.headers;
                resourceInfo.res = { //construct a self-defined res object
                    statusCode: response.statusCode,
                    headers: headers,
                };

                resourceInfo.statusCode = response.statusCode;
                resourceInfo.resHeader = headers;
                resourceInfo.resBody = '';
                resourceInfo.length = resourceInfo.resBody.length;

                recorder.updateRecord(resourceInfoId, resourceInfo);
            });
        }

        /**
        * consume the message in queue when the proxy ws is not ready yet
        * will handle them from the first one-by-one
        */
        proxyWs.onopen = function () {
            // console.log("onopen")
            // process.exit(0)
            while (clientMsgQueue.length > 0) {
                const message = clientMsgQueue.shift();
                proxyWs.send(message);
            }
        }

        // https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent#Status_codes
        proxyWs.onerror = function (e) {
            console.log("proxyWs.onerror",e.message)
            // process.exit(0)
            wsClient.close(1001, e.message);
            proxyWs.close(1001);
        }

        proxyWs.onmessage = function (event) {
            // console.log("xxxx")
            // process.exit(0)
            recordMessage(event, false);
            wsClient.readyState === 1 && wsClient.send(event.data);
        }

        proxyWs.onclose = function (event) {
            // console.log("proxyWs.onclose")
            // process.exit(0)
            logUtil.debug(`proxy ws closed with code: ${event.code} and reason: ${event.reason}`);
            const targetCloseInfo = getCloseFromOriginEvent(event);
            wsClient.readyState !== 3 && wsClient.close(targetCloseInfo.code, targetCloseInfo.reason);
        }

        wsClient.onmessage = function (event) {
            recordMessage(event, true);
            sendProxyMessage(event);
        }

        wsClient.onclose = function (event) {
            logUtil.debug(`original ws closed with code: ${event.code} and reason: ${event.reason}`);
            const targetCloseInfo = getCloseFromOriginEvent(event);
            proxyWs.readyState !== 3 && proxyWs.close(targetCloseInfo.code, targetCloseInfo.reason);
        }
    } catch (e) {
        logUtil.debug('WebSocket Proxy Error:' + e.message);
        logUtil.debug(e.stack);
        console.error(e);
    }
}

/**
* get request info from the ws client, includes:
 host
 port
 path
 protocol  ws/wss

 @param @required wsClient the ws client of WebSocket
*
*/
function getWsReqInfo(wsReq) {
    const headers = wsReq.headers || {};
    const host = headers.host;
    const hostName = host.split(':')[0];
    const port = host.split(':')[1];

    // TODO 如果是windows机器，url是不是全路径？需要对其过滤，取出
    const path = wsReq.url || '/';

    const isEncript = wsReq.connection && wsReq.connection.encrypted;
    /**
     * construct the request headers based on original connection,
     * but delete the `sec-websocket-*` headers as they are already consumed by AnyProxy
     */
    const getNoWsHeaders = function () {
        const originHeaders = Object.assign({
            // "Accept-Encoding": "gzip, deflate, br",
            // "Accept-Language": "en-US,en;q=0.9"
        }, headers);
        const originHeaderKeys = Object.keys(originHeaders);
        originHeaderKeys.forEach((key) => {
            // if the key matchs 'sec-websocket', delete it
            if (/sec-websocket-key/ig.test(key)) {
                delete originHeaders[key];
            }
        });
        // originHeaders originHeaders["sec-websocket-extensions"]
        delete originHeaders.connection;
        delete originHeaders.upgrade;
        return originHeaders;
    }


    return {
        headers: headers, // the full headers of origin ws connection
        noWsHeaders: getNoWsHeaders(),
        hostName: hostName,
        port: port,
        path: path,
        protocol: isEncript ? 'wss' : 'ws'
    };
}

class RequestHandler {

    /**
     * Creates an instance of RequestHandler.
     *
     * @param {object} config
     * @param {boolean} config.forceProxyHttps proxy all https requests
     * @param {boolean} config.dangerouslyIgnoreUnauthorized
       @param {number} config.httpServerPort  the http port AnyProxy do the proxy
     * @param {object} rule
     * @param {Recorder} recorder
     *
     * @memberOf RequestHandler
     */
    constructor(config, recorder) {
        const reqHandlerCtx = this;
        this.httpServerPort = config.httpServerPort;
        this.forceProxyHttps = config.forceProxyHttps;
        this.dangerouslyIgnoreUnauthorized = config.dangerouslyIgnoreUnauthorized;
        this.wsIntercept = config.wsIntercept;
        // const default_rule = util.freshRequire('./rule_default');
        // const userRule = util.merge(default_rule, rule);
        const userRule = config.rule

        reqHandlerCtx.userRequestHandler = getUserReqHandler.apply(reqHandlerCtx, [userRule, recorder]);
        reqHandlerCtx.wsHandler = getWsHandler.bind(this, userRule, recorder);

        const httpsServerMgr =
            reqHandlerCtx.httpsServerMgr = new HttpsServerMgr({
                handler: reqHandlerCtx.userRequestHandler,
                wsHandler: reqHandlerCtx.wsHandler // websocket
            });
        reqHandlerCtx.conns = new Map();
        reqHandlerCtx.cltSockets = new Map();
        // this.connectReqHandler = getConnectReqHandler(reqHandlerCtx, userRule, recorder, reqHandlerCtx.httpsServerMgr);

        async function _connect_should_intercept(requestDetail) {
            const should = (await userRule.beforeDealHttpsRequest(requestDetail)) | 0;
            return should !== 0 || reqHandlerCtx.forceProxyHttps;
        }

        function _connect_data_ws_flags(cltSocket, requestStream) {
            return new Promise(function (resolve, reject) {
                let resolved = false;
                let ws_flags = 0
                cltSocket.on('data', function (chunk) {
                    requestStream.push(chunk);
                    if (!resolved) {
                        resolved = true;
                        try {
                            const chunkString = chunk.toString();
                            if (chunkString.indexOf('GET ') === 0) {
                                ws_flags |= 1;
                                // if there is '/do-not-proxy' in the request, do not intercept the websocket
                                // to avoid AnyProxy itself be proxied
                                if (reqHandlerCtx.wsIntercept && chunkString.indexOf('GET /do-not-proxy') !== 0) {
                                    ws_flags |= 2;
                                }
                            }
                        } catch (e) {
                            console.error(e);
                        }
                        resolve(ws_flags);
                    }
                });
                cltSocket.on('error', async function (error) {
                    logUtil.printLog(util.collectErrorLog(error), logUtil.T_ERR);
                    console.error(error);
                    try {
                        await userRule.onClientSocketError(error); //TODO: , requestDetail)
                    }
                    catch (e) {
                        console.error(e);
                    }
                    reject(error)
                });
                cltSocket.on('end', function () {
                    requestStream.push(null);
                });
            });
        }

        async function _connect_get_server_info(host, targetPort, shouldIntercept, interceptWsRequest) {
            // determine the request target
            if (!shouldIntercept) {
                // for ws request, redirect them to local ws server
                return interceptWsRequest
                    ? // localHttpServer
                        {
                            host: 'localhost',
                            port: reqHandlerCtx.httpServerPort
                        }
                    : // originServer
                        {
                            host,
                            port: (targetPort === 80) ? 443 : targetPort
                        }
                ;
            } else {
                const info = await httpsServerMgr.getSharedHttpsServer(host);
                return {
                    host: info.host,
                    port: info.port
                };
            }
        }


        function _connect_req_connect(
            shouldIntercept, serverInfo, requestStream, cltSocket,
            cb)
        {
            const {host, port} = serverInfo;
            const host_port = host + ':' + port;
            const conn = net.connect(port, host, function () {
                requestStream.pipe(conn);
                if (global._throttle && !shouldIntercept) // throttle for direct-foward https
                    conn.pipe(global._throttle.throttle()).pipe(cltSocket);
                else
                    conn.pipe(cltSocket);
                cb();
            });
            reqHandlerCtx.conns.set(host_port, conn);
            reqHandlerCtx.cltSockets.set(host_port, cltSocket);
            return conn;
        }

        this.connectReqHandler = async function (req, cltSocket, head) {
            const [host, targetPort] = req.url.split(':');

            logUtil.printLog(color.green('received https CONNECT request ' + host));

            let requestDetail = {
                host: req.url,
                _req: req
            };
            let resourceInfo = null;
            let resourceInfoId = -1;
            const requestStream = new CommonReadableStream();

            let interceptWsRequest = false;
            // determine whether to use the man-in-the-middle server
            let shouldIntercept = false;

            /*
              1. write HTTP/1.1 200 to client
              2. get request data
              3. tell if it is a websocket request
              4.1 if (websocket || do_not_intercept) --> pipe to target server
              4.2 else --> pipe to local server and do man-in-the-middle attack
            */

            try {
                // mark socket connection as established, to detect the request protocol
                cltSocket.write('HTTP/' + req.httpVersion + ' 200 OK\r\n\r\n', 'UTF-8',
                    async function() {
                        const ws_flags = await _connect_data_ws_flags(cltSocket, requestStream);
                        if (ws_flags > 0) {
                            shouldIntercept = false; // websocket, do not intercept
                            interceptWsRequest = ws_flags > 1;
                        }
                        else
                            shouldIntercept = await _connect_should_intercept(requestDetail);

                        if (shouldIntercept)
                            logUtil.printLog('will forward to local https server');
                        else
                            logUtil.printLog('will bypass the man-in-the-middle proxy');

                        __connect_append_record(req);

                        const serverInfo = await _connect_get_server_info(host, targetPort, shouldIntercept, interceptWsRequest);
                        if (!serverInfo.port || !serverInfo.host)
                            throw new Error('failed to get https server info');

                        _connect_req_connect(
                            shouldIntercept, serverInfo, requestStream, cltSocket,
                            __connect_update_record
                        ).on('error', __on_err);
                    }
                );
            }
            catch(error) {
                __on_err(error)
            }

            async function __on_err(error) {
                logUtil.printLog(util.collectErrorLog(error), logUtil.T_ERR);
                console.error(error)
                try {
                    await userRule.onConnectError(requestDetail, error);
                }
                catch (e) { }
                try {
                    let errorHeader = 'Proxy-Error: true\r\n';
                    errorHeader += 'Proxy-Error-Message: ' + (error || 'null') + '\r\n';
                    errorHeader += 'Content-Type: text/html\r\n';
                    cltSocket.write('HTTP/1.1 502\r\n' + errorHeader + '\r\n\r\n');
                }
                catch (e) { }
            }

            function __connect_append_record(req) {
                if (recorder) {
                    resourceInfo = {
                        host,
                        method: req.method,
                        path: '',
                        url: 'https://' + host,
                        req,
                        startTime: new Date().getTime()
                    };
                    resourceInfoId = recorder.appendRecord(resourceInfo);
                }
            }

            function __connect_update_record() {
                if (recorder) {
                    resourceInfo.endTime = new Date().getTime();
                    resourceInfo.statusCode = '200';
                    resourceInfo.resHeader = {};
                    resourceInfo.resBody = '';
                    resourceInfo.length = 0;
                    recorder && recorder.updateRecord(resourceInfoId, resourceInfo);
                }
            }
        }
    }
}



module.exports = RequestHandler;

'use strict';

const http = require('http'),
    https = require('https'),
    net = require('net'),
    url = require('url'),
    color = require('colorful'),
    Buffer = require('buffer').Buffer,
    util = require('./util'),
    Stream = require('stream'),
    logUtil = require('./log'),
    HttpsServerMgr = require('./httpsServerMgr'),
    Readable = require('stream').Readable;

// to fix issue with TLS cache, refer to: https://github.com/nodejs/node/issues/8368
https.globalAgent.maxCachedSessions = 0;

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

    const proxyReq = (
        protocol === 'https' ? https : http
    ).request(options, _request_cb)

    proxyReq.useChunkedEncodingByDefault = true;
    proxyReq.once('error', reject);
    proxyReq.end(reqData);

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
        const originHeaders = Object.assign({}, headers);
        const originHeaderKeys = Object.keys(originHeaders);
        originHeaderKeys.forEach((key) => {
            // if the key matchs 'sec-websocket', delete it
            if (/sec-websocket/ig.test(key)) {
                delete originHeaders[key];
            }
        });

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

    return async function (req, userRes) {
        // console.time('req')
        /*
        note
          req.url is wired
          in http  server: http://www.example.com/a/b/c
          in https server: /a/b/c
        */

        const host = req.headers.host;
        const protocol = (!!req.connection.encrypted && !(/^http:/).test(req.url)) ? 'https' : 'http';



        // try find fullurl https://github.com/alibaba/anyproxy/issues/419
        // const fullUrl = protocol === 'http' ? req.url : (protocol + '://' + host + req.url);
        let fullUrl = protocol + '://' + host + req.url;
        if (protocol === 'http') {
            const reqUrlPattern = url.parse(req.url);
            if (reqUrlPattern.host && reqUrlPattern.protocol)
                fullUrl = req.url;
        }



        const urlPattern = url.parse(fullUrl);
        const path = urlPattern.path;
        const chunkSizeThreshold = DEFAULT_CHUNK_COLLECT_THRESHOLD;

        let reqData;
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
                    resourceInfo.reqBody = reqData.toString(); //TODO: deal reqBody in webInterface.js
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
                reqData = Buffer.concat(_fetch_post_data);
                _fetch_post_data.length = 0;
                resolve();
            });
        }


        /**
         * prepare detailed request info
         */
        const prepareRequestDetail = function () {
            const options = {
                hostname: urlPattern.hostname || req.headers.host,
                port: urlPattern.port || req.port || (/https/.test(protocol) ? 443 : 80),
                path,
                method: req.method,
                headers: req.headers
            };
            requestDetail = {
                requestOptions: options,
                protocol,
                url: fullUrl,
                requestData: reqData,
                response: null,
                _req: req
            };
            // return Promise.resolve();
        };


        let responseData;

        // fetch complete request data
        try {
            await fetch_promise;
            prepareRequestDetail()
            _record_request();
            const userModifiedInfo = (
                await userRule.beforeSendRequest(
                    requestDetail //Object.assign({}, requestDetail)
                )
            );
            const userConfig = (userModifiedInfo === null)
                    ? requestDetail
                    : userModifiedInfo
            ;
            // return (userModifiedInfo === null)
            //     ? {
            //         'protocol': requestDetail['protocol'],
            //         'requestOptions': requestDetail['requestOptions'],
            //         'requestData': requestDetail['requestData'],
            //         'response': requestDetail['response'],
            //     }
            //     : {
            //         'protocol': userModifiedInfo['protocol'],
            //         'requestOptions': userModifiedInfo['requestOptions'],
            //         'requestData': userModifiedInfo['requestData'],
            //         'response': userModifiedInfo['response'],
            //     }
            //     ;
            responseData = await _fetch_route_user_config(userConfig);
            responseData = await _fetch_invoke_rule_b4_client(responseData);
        }
        catch(error) {
            responseData = await _fetch_catch(error);
        }

        const responseInfo = responseData.response;
        if (!responseInfo)
            _fetch_response_catch(new Error('failed to get response info'));
        else if (!responseInfo.statusCode)
            _fetch_response_catch(new Error('failed to get response status code'));
        else if (!responseInfo.header)
            _fetch_response_catch(new Error('filed to get response header'))
        else {
            try {                
                _record_reponse(
                    sendFinalResponse( responseInfo )
                );
            }
            catch(error) {
                _fetch_response_catch(error);
            }
        }
        async function _fetch_route_user_config(userConfig) {
            if (userConfig.response) {
                // user-assigned local response
                userConfig._directlyPassToRespond = true;
                return userConfig;
            } else if (userConfig.requestOptions) {
                const remoteResponse = await fetchRemoteResponse(userConfig.protocol, userConfig.requestOptions, userConfig.requestData, {
                    dangerouslyIgnoreUnauthorized: reqHandlerCtx.dangerouslyIgnoreUnauthorized,
                    chunkSizeThreshold,
                });
                return {
                    response: {
                        statusCode: remoteResponse.statusCode,
                        header: remoteResponse.header,
                        body: remoteResponse.body,
                        rawBody: remoteResponse.rawBody
                    },
                    _res: remoteResponse._res,
                };
            } else {
                throw new Error('lost response or requestOptions, failed to continue');
            }
        }

        async function _fetch_invoke_rule_b4_client(responseData) {
            if (responseData._directlyPassToRespond) {
                return responseData;
            } else if (responseData.response.body && responseData.response.body instanceof CommonReadableStream) { // in stream mode
                return responseData;
            } else {
                // TODO: err etimeout
                return (
                    await userRule.beforeSendResponse(
                        Object.assign({}, requestDetail),
                        Object.assign({}, responseData)
                    )
                ) || responseData;
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
        const proxyWs = new WebSocket(wsUrl, '', {
            rejectUnauthorized: !self.dangerouslyIgnoreUnauthorized,
            headers: serverInfo.noWsHeaders
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
            while (clientMsgQueue.length > 0) {
                const message = clientMsgQueue.shift();
                proxyWs.send(message);
            }
        }

        // https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent#Status_codes
        proxyWs.onerror = function (e) {
            wsClient.close(1001, e.message);
            proxyWs.close(1001);
        }

        proxyWs.onmessage = function (event) {
            recordMessage(event, false);
            wsClient.readyState === 1 && wsClient.send(event.data);
        }

        proxyWs.onclose = function (event) {
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
    constructor(config, rule, recorder) {
        const reqHandlerCtx = this;
        this.forceProxyHttps = false;
        this.dangerouslyIgnoreUnauthorized = false;
        this.httpServerPort = '';
        this.wsIntercept = false;

        if (config.forceProxyHttps)
            this.forceProxyHttps = true;

        if (config.dangerouslyIgnoreUnauthorized)
            this.dangerouslyIgnoreUnauthorized = true;

        if (config.wsIntercept)
            this.wsIntercept = config.wsIntercept;

        this.httpServerPort = config.httpServerPort;

        // const default_rule = util.freshRequire('./rule_default');
        // const userRule = util.merge(default_rule, rule);
        const userRule = {
            beforeSendRequest: rule.beforeSendRequest || afun_null,
            beforeSendResponse: rule.beforeSendResponse || afun_null,
            beforeDealHttpsRequest: rule.beforeDealHttpsRequest || afun_null,
            onError: rule.onError || afun_null,
            onConnectError: rule.onConnectError || afun_null,
            onClientSocketError: rule.onClientSocketError || afun_null,
        }

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
            let should = await userRule.beforeDealHttpsRequest(requestDetail);
            return should !== null
                ? should
                : reqHandlerCtx.forceProxyHttps
            ;
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
                    try {
                        await userRule.onClientSocketError(requestDetail, error);
                    }
                    catch (e) { }
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

async function afun_null() {return null;}

module.exports = RequestHandler;

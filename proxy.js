'use strict';

const http = require('http'),
  async = require('async'),
  // color = require('colorful'),
  certMgr = require('./lib/certMgr'),
  // Recorder = require('./lib/recorder'),
  logUtil = require('./lib/log'),
  // util = require('./lib/util'),
  events = require('events'),
  wsServerMgr = require('./lib/wsServerMgr')
;

// const memwatch = require('memwatch-next');

// setInterval(() => {
//   console.log(process.memoryUsage());
//   const rss = Math.ceil(process.memoryUsage().rss / 1000 / 1000);
//   console.log('Program is using ' + rss + ' mb of Heap.');
// }, 1000);

// memwatch.on('stats', (info) => {
//   console.log('gc !!');
//   console.log(process.memoryUsage());
//   const rss = Math.ceil(process.memoryUsage().rss / 1000 / 1000);
//   console.log('GC !! Program is using ' + rss + ' mb of Heap.');

//   // var heapUsed = Math.ceil(process.memoryUsage().heapUsed / 1000);
//   // console.log("Program is using " + heapUsed + " kb of Heap.");
//   // console.log(info);
// });

const T_TYPE_HTTP = 'http',
  T_TYPE_HTTPS = 'https',
  DEFAULT_TYPE = T_TYPE_HTTP;

const PROXY_STATUS_INIT = 'INIT';
const PROXY_STATUS_READY = 'READY';
const PROXY_STATUS_CLOSED = 'CLOSED';

/**
 *
 * @class ProxyCore
 * @extends {events.EventEmitter}
 */
class ProxyCore extends events.EventEmitter {

  /**
   * Creates an instance of ProxyCore.
   *
   * @param {object} config - configs
   * @param {number} config.port - port of the proxy server
   * @param {object} [config.rule=null] - rule module to use
   * @param {string} [config.type=http] - type of the proxy server, could be 'http' or 'https'
   * @param {strign} [config.hostname=localhost] - host name of the proxy server, required when this is an https proxy
   * @param {number} [config.throttle] - speed limit in kb/s
   * @param {boolean} [config.forceProxyHttps=false] - if proxy all https requests
   * @param {boolean} [config.silent=false] - if keep the console silent
   * @param {boolean} [config.dangerouslyIgnoreUnauthorized=false] - if ignore unauthorized server response
   * @param {object} [config.recorder] - recorder to use
   * @param {boolean} [config.wsIntercept] - whether intercept websocket
   *
   * @memberOf ProxyCore
   */
  constructor(config) {
    super();

    this.status = PROXY_STATUS_INIT;
    this.proxyPort = config.port;
    this.proxyType = /https/i.test(config.type || DEFAULT_TYPE) ? T_TYPE_HTTPS : T_TYPE_HTTP;
    this.proxyHostName = config.hostname || 'localhost';
    this.recorder = config.recorder;

    // if (parseInt(process.versions.node.split('.')[0], 10) < 4) {
    //   throw new Error('node.js >= v4.x is required for anyproxy');
    // }

    if (!certMgr.ifRootCAFileExists()) {
      certMgr.generateRootCA((error, keyPath, crtPath) => {
        if (error) {
          console.error('failed to generate rootCA', error);
          process.exit(0);
        }
        this._setup(config);
        // else {
        //   const certDir = path.dirname(keyPath);
        //   console.log(`The cert is generated at ${certDir}. Please trust the ${color.bold('rootCA.crt')}.`);
        //   // TODO: console.log('guide to install');
        //   openFolderOfFile(crtPath);
        // }
      });
    }
    else {
      this._setup(config);
    }


  }
  _setup(config) {
    const rule = config.rule || {};
    // if (config.forceProxyHttps && !certMgr.ifRootCAFileExists()) {
    //   logUtil.printLog('You can run `anyproxy-ca` to generate one root CA and then re-run this command');
    //   throw new Error('root CA not found. Please run `anyproxy-ca` to generate one first.');
    // }
    // else
    if (this.proxyType === T_TYPE_HTTPS && !config.hostname) {
      throw new Error('hostname is required in https proxy');
    } else if (!this.proxyPort) {
      throw new Error('proxy port is required');
    }
    // else if (!this.recorder) {
    //   throw new Error('recorder is required');
    // }
    else if (config.forceProxyHttps && rule && rule.beforeDealHttpsRequest) {
      logUtil.printLog('both "-i(--intercept)" and rule.beforeDealHttpsRequest are specified, the "-i" option will be ignored.', logUtil.T_WARN);
      config.forceProxyHttps = false;
    }

    this.httpProxyServer = null;
    this.requestHandler = null;

    // copy the rule to keep the original proxyRule independent
    this.proxyRule = rule;
    rule.beforeSendRequest || (rule.beforeSendRequest = NULL_FN);
    rule.beforeSendResponse || (rule.beforeSendResponse = NULL_FN);
    rule.beforeDealHttpsRequest || (rule.beforeDealHttpsRequest = NULL_FN);
    rule.onError || (rule.onError = NULL_FN);
    rule.onConnectError || (rule.onConnectError = NULL_FN);
    rule.onClientSocketError || (rule.onClientSocketError = NULL_FN);
    async function NULL_FN() {return null;}


    if (config.silent) {
      logUtil.setPrintStatus(false);
    }

    if (config.throttle) {
      logUtil.printLog('throttle :' + config.throttle + 'kb/s');
      const rate = parseInt(config.throttle, 10);
      if (rate < 1) {
        throw new Error('Invalid throttle rate value, should be positive integer');
      }

      const ThrottleGroup = require('stream-throttle').ThrottleGroup;
      global._throttle = new ThrottleGroup({ rate: 1024 * rate }); // rate - byte/sec
    }

    // init recorder
    this.recorder = config.recorder;

    // init request handler
    const RequestHandler = require('./lib/requestHandler.js') //util.freshRequire('./requestHandler');
    this.requestHandler = new RequestHandler(config, this.recorder);
  }
  /**
  * manage all created socket
  * for each new socket, we put them to a map;
  * if the socket is closed itself, we remove it from the map
  * when the `close` method is called, we'll close the sockes before the server closed
  *
  * @param {Socket} the http socket that is creating
  * @returns undefined
  * @memberOf ProxyCore
  */
  handleExistConnections(socket) {
    const self = this;
    self.socketIndex ++;
    const key = `socketIndex_${self.socketIndex}`;
    self.socketPool[key] = socket;

    // if the socket is closed already, removed it from pool
    socket.on('close', () => {
      delete self.socketPool[key];
    });
  }
  /**
   * start the proxy server
   *
   * @returns ProxyCore
   *
   * @memberOf ProxyCore
   */
  start() {
    const self = this;
    self.socketIndex = 0;
    self.socketPool = {};
    if (self.status !== PROXY_STATUS_INIT) {
      throw new Error('server status is not PROXY_STATUS_INIT, can not run start()');
    }
    async.series(
      [
        // create proxy server
        function (callback) {
          if (self.proxyType === T_TYPE_HTTPS) {
            certMgr.getCertificate(self.proxyHostName, function (err, keyContent, crtContent) {
              if (err) {
                callback(err);
              }
              else {
                self.httpProxyServer = require('https').createServer({
                  key: keyContent,
                  cert: crtContent
                }, self.requestHandler.userRequestHandler);
                callback(null);
              }
            });
          }
          else {
            self.httpProxyServer = http.createServer(self.requestHandler.userRequestHandler);
            callback(null);
          }
        },

        //handle CONNECT request for https over http
        function (callback) {
          self.httpProxyServer.on('connect', self.requestHandler.connectReqHandler);
          callback(null);
        },

        function (callback) {
          wsServerMgr.getWsServer({
            server: self.httpProxyServer,
            connHandler: self.requestHandler.wsHandler
          });
          // remember all sockets, so we can destory them when call the method 'close';
          self.httpProxyServer.on('connection', (socket) => {
            self.handleExistConnections.call(self, socket);
          });
          callback(null);
        },

        //start proxy server
        function (callback) {
          self.httpProxyServer.listen(self.proxyPort);
          callback(null);
        },
      ],

      //final callback
      async function (err, result) {
        if (!err) {
          const tipText = (self.proxyType === T_TYPE_HTTP ? 'Http' : 'Https') + ' proxy started on port ' + self.proxyPort;
          logUtil.printLog(tipText)
          // logUtil.printLog(color.green(tipText));

          if (self.webServerInstance) {
            logUtil.printLog(
              'web interface started on port ' + self.webServerInstance.webPort
              // color.green(webTip)
            );
          }

          const ruleSummary = self.proxyRule.summary;
          if (ruleSummary) {
              const ruleSummaryString = (typeof ruleSummary === 'string')
                ? ruleSummary
                : await ruleSummary()
              ;
              logUtil.printLog(
                // color.green(
                  `Active rule is: ${ruleSummaryString}`
                // )
              );
          }

          self.status = PROXY_STATUS_READY;
          self.emit('ready');
        }
        else {
          logUtil.printLog(
            // color.red(
              'err when start proxy server :('
            // )
          , logUtil.T_ERR);
          logUtil.printLog(err, logUtil.T_ERR);
          self.emit('error', {
            error: err
          });
        }
      }
    );

    return self;
  }


  /**
   * close the proxy server
   *
   * @returns ProxyCore
   *
   * @memberOf ProxyCore
   */
  close() {
    // clear recorder cache
    return new Promise((resolve) => {
      if (this.httpProxyServer) {
        // destroy conns & cltSockets when closing proxy server
        for (const connItem of this.requestHandler.conns) {
          const key = connItem[0];
          const conn = connItem[1];
          logUtil.printLog(`destorying https connection : ${key}`);
          conn.end();
        }

        for (const cltSocketItem of this.requestHandler.cltSockets) {
          const key = cltSocketItem[0];
          const cltSocket = cltSocketItem[1];
          logUtil.printLog(`closing https cltSocket : ${key}`);
          cltSocket.end();
        }

        if (this.socketPool) {
          for (const key in this.socketPool) {
            this.socketPool[key].destroy();
          }
        }

        this.httpProxyServer.close((error) => {
          if (error) {
            console.error(error);
            logUtil.printLog(`proxy server close FAILED : ${error.message}`, logUtil.T_ERR);
          } else {
            this.httpProxyServer = null;

            this.status = PROXY_STATUS_CLOSED;
            logUtil.printLog(`proxy server closed at ${this.proxyHostName}:${this.proxyPort}`);
          }
          resolve(error);
        });
      } else {
        resolve();
      }
    })
  }
}

/**
 * start proxy server as well as recorder and webInterface
 */
class ProxyServer extends ProxyCore {
  /**
   *
   * @param {object} config - config
   * @param {object} [config.webInterface] - config of the web interface
   * @param {boolean} [config.webInterface.enable=false] - if web interface is enabled
   * @param {number} [config.webInterface.webPort=8002] - http port of the web interface
   */
  constructor(config) {
    // prepare a recorder

    const recorder = null //new Recorder();

    const configForCore = Object.assign({
      recorder,
    }, config);

    super(configForCore);

    this.proxyWebinterfaceConfig = config.webInterface;
    this.recorder = recorder;
    this.webServerInstance = null;
  }

  start() {
    // start web interface if neeeded
    if (this.proxyWebinterfaceConfig && this.proxyWebinterfaceConfig.enable) {
      const WebInterface = require('./lib/webInterface');
      this.webServerInstance = new WebInterface(this.proxyWebinterfaceConfig, this.recorder);
      // start web server
      this.webServerInstance.start().then(() => {
        // start proxy core
        super.start();
      }).catch((e) => {
        this.emit('error', e);
      });
    } else {
      super.start();
    }
  }

  close() {
    return new Promise((resolve, reject) => {
      super.close()
        .then((error) => {
          if (error) {
            resolve(error);
          }
        });

      if (this.recorder) {
        logUtil.printLog('clearing cache file...');
        this.recorder.clear();
      }
      const tmpWebServer = this.webServerInstance;
      this.recorder = null;
      this.webServerInstance = null;
      if (tmpWebServer) {
        logUtil.printLog('closing webserver...');
        tmpWebServer.close((error) => {
          if (error) {
            console.error(error);
            logUtil.printLog(`proxy web server close FAILED: ${error.message}`, logUtil.T_ERR);
          } else {
            logUtil.printLog(`proxy web server closed at ${this.proxyHostName} : ${this.webPort}`);
          }

          resolve(error);
        })
      } else {
        resolve(null);
      }
    });
  }
}

module.exports.ProxyCore = ProxyCore;
module.exports.ProxyServer = ProxyServer;
// module.exports.ProxyRecorder = Recorder;
// module.exports.ProxyWebServer = WebInterface;
module.exports.utils = {
  systemProxyMgr: require('./lib/systemProxyMgr'),
  certMgr,
};

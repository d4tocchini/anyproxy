
require('../.package.js');

pkg(module, function ({init, deps, deps_dev}) {

    init({
        "name": "anyproxy",
        "version": "4.1.0",
        "description": "A fully configurable HTTP/HTTPS proxy in Node.js",
        "main": "proxy.js",
        "bin": {
          "anyproxy-ca": "bin/anyproxy-ca",
          "anyproxy": "bin/anyproxy"
        },
        "scripts": {
          "_prepublish": "npm run buildweb",
          "test": "node test.js",
          "lint": "eslint .",
          "testserver": "node test/server/startServer.js",
          "testOutWeb": "jasmine test/spec_outweb/test_realweb_spec.js",
          "buildweb": "NODE_ENV=production webpack --config web/webpack.config.js --colors",
          "webserver": "NODE_ENV=test webpack --config web/webpack.config.js --colors --watch",
          "doc:serve": "node build_scripts/prebuild-doc.js && gitbook serve ./docs-src ./docs --log debug",
          "doc:build": "./build_scripts/build-doc-site.sh"
        },
        "_pre-commit": [
          "lint"
        ],
        "repository": {
          "type": "git",
          "url": "https://github.com/alibaba/anyproxy"
        },
        "author": "ottomao@gmail.com",
        "license": "Apache-2.0",
        "engines": {
          "node": ">=6.0.0"
        },
        "_dependencies": {
            "async_": "~0.9.0",
            "async": "3.1.0",
            "async-task-mgr": ">=1.1.0",
            "body-parser": "^1.19.0",
            "brotli": "^1.3.2",
            "classnames": "^2.2.6",
            "clipboard-js": "^0.3.6",
            "co": "^4.6.0",
            "colorful": "^2.1.0",
            "commander": "~2.11.0",
            "component-emitter": "^1.3.0",
            "compression": "^1.7.4",
            "es6-promise": "^3.3.1",
            "express": "^4.17.1",
            "fast-json-stringify": "^0.17.0",
            "iconv-lite": "^0.5.0",
            "ip": "^0.3.2",
            "juicer": "^0.6.15",
            "mime-types": "2.1.24",
            "moment": "^2.24.0",
            "node-easy-cert": "^1.0.0",
            "pug": "^2.0.4",
            "qrcode-npm": "0.0.3",
            "request": "^2.88.0",
            "stream-throttle": "^0.1.3",
            "thunkify": "^2.1.2",
            "ws": "^5.1.0"
          },
    });

    deps({

        "whatwg-fetch": "^1.0.0",
        "svg-inline-react": "^1.0.2",
        "nedb": "^1.8.0",
        "inquirer": "^5.2.0"

    })
    //   "_deps": {
    //     "!!!! global": "4.4.0",
    //     "!!!! core-js": "~2.6.2",
    //     "!!!! @sentry/browser": "^5.7.1",
    //     "@angular/animations": "~8.2.11",
    //     "@angular/common": "~8.2.11",
    //     "@angular/compiler": "~8.2.11",
    //     "@angular/core": "~8.2.11",
    //     "@angular/forms": "~8.2.11",
    //     "@angular/http": "~7.2.15",
    //     "@angular/platform-browser": "~8.2.11",
    //     "@angular/platform-browser-dynamic": "~8.2.11",
    //     "@angular/router": "~8.2.11",
    //     "angular-plotly.js": "^1.4.2",
    //     "bn.js": "5.0.0",
    //     "dexie": "^2.0.4",
    //     "ethjs": "~0.4.0",
    //     "ethjs-account": "^0.1.4",
    //     "ethjs-provider-signer": "^0.1.4",
    //     "ethjs-signer": "0.1.1",
    //     "material-design-icons": "~3.0.1",
    //     "material-design-lite": "~1.3.0",
    //     "plotly.js": "^1.50.1",
    //     "qrcodejs2": "0.0.2",
    //     "rxjs": "~6.5.3",
    //     "textarea-caret": "^3.1.0",
    //     "tslib": "~1.10.0",
    //     "socket.io-client": "^2.2.0",
    //     "webtorrent": "^0.107.16",
    //     "zone.js": "~0.10.2"
    //   },
    //   "_devdeps": {
    //     "prettier": "1.18.2"
    //   },

    deps_dev({

        // "antd": "^2.5.0",
        // "autoprefixer": "^6.4.1",
        // "babel-core": "^6.14.0",
        // "babel-eslint": "^7.0.0",
        // "babel-loader": "^6.2.5",
        // "babel-plugin-import": "^1.0.0",
        // "babel-plugin-transform-runtime": "^6.15.0",
        // "babel-polyfill": "^6.13.0",
        // "babel-preset-es2015": "^6.13.2",
        // "babel-preset-react": "^6.11.1",
        // "babel-preset-stage-0": "^6.5.0",
        // "babel-register": "^6.11.6",
        // "babel-runtime": "^6.11.6",
        // "css-loader": "^0.23.1",
        // "eslint": "^3.5.0",
        // "eslint-config-airbnb": "^15.1.0",
        // "eslint-plugin-import": "^2.7.0",
        // "eslint-plugin-jsx-a11y": "^5.1.1",
        // "eslint-plugin-react": "^7.4.0",
        // "extract-text-webpack-plugin": "^3.0.2",
        // "file-loader": "^0.9.0",
        // "jasmine": "^2.5.3",
        // "koa": "^1.2.1",
        // "koa-body": "^1.4.0",
        // "koa-router": "^5.4.0",
        // "koa-send": "^3.2.0",
        // "less": "^2.7.1",
        // "less-loader": "^2.2.3",
        // "node-simhash": "^0.1.0",
        // "nodeunit": "^0.9.1",
        // "phantom": "^4.0.0",
        // "postcss-loader": "^0.13.0",
        // "pre-commit": "^1.2.2",
        // "react": "^15.3.1",
        // "react-addons-perf": "^15.4.0",
        // "react-dom": "^15.3.1",
        // "react-json-tree": "^0.10.0",
        // "react-redux": "^4.4.5",
        // "react-tap-event-plugin": "^1.0.0",
        // "redux": "^3.6.0",
        // "redux-saga": "^0.11.1",
        // "stream-equal": "0.1.8",
        // "style-loader": "^0.13.1",
        // "svg-inline-loader": "^0.7.1",
        // "tunnel": "^0.0.6",
        // "url-loader": "^0.5.7",
        // "webpack": "^3.10.0",
        // "worker-loader": "^0.7.1"

    });
});
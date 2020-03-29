'use strict';

/*
* handle all request error here,
*
*/

const path = require('path');

function pug_compile(filepath) {
  const pug = require('pug');
  pug_compile = function(filepath) {
    return pug.compileFile(filepath);
  }
  return pug_compile(filepath);
}

let error502PugFn;
let certPugFn;

/**
* get error content for certification issues
*/
function getCertErrorContent(error, fullUrl) {
  let content;
  const title = 'The connection is not private. ';
  let explain = 'There are error with the certfication of the site.';
  switch (error.code) {
    case 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY': {
      explain = 'The certfication of the site you are visiting is not issued by a known agency, '
        + 'It usually happenes when the cert is a self-signed one.</br>'
        + 'If you know and trust the site, you can run AnyProxy with option <strong>-ignore-unauthorized-ssl</strong> to continue.'

      break;
    }
    default: {
      explain = ''
      break;
    }
  }

  certPugFn || (
    certPugFn =  pug_compile(path.join(__dirname, '../resource/cert_error.pug'))
  );

  try {
    content = certPugFn({
      title: title,
      explain: explain,
      code: error.code
    });
  } catch (parseErro) {
    content = error.stack;
  }

  return content;
}

/*
* get the default error content
*/
function getDefaultErrorCotent(error, fullUrl) {
  let content;
  error502PugFn || (
    error502PugFn = pug_compile(path.join(__dirname, '../resource/502.pug'))
  );
  try {
    content = error502PugFn({
      error,
      url: fullUrl,
      errorStack: error.stack.split(/\n/)
    });
  } catch (parseErro) {
    content = error.stack;
  }

  return content;
}

/*
* get mapped error content for each error
*/
module.exports.getErrorContent = function (error, fullUrl) {
  let content = '';
  error = error || {};
  switch (error.code) {
    case 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY': {
      content = getCertErrorContent(error, fullUrl);
      break;
    }
    default: {
      content = getDefaultErrorCotent(error, fullUrl);
      break;
    }
  }

  return content;
}

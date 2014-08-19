anyproxy
==========

## Intro
While there are lots of proxy written by nodejs in github, most of them can not handle users' HTTPS requests perfectly. A typical problem is that the browser will throw warning like INVALID_CERTIFICATE when they want to intercept some https requests. 

A simple and fast solution is to short the traffic between the user and the target server. That is to say, what the proxy do is to forward all the traffic of both sides, without intercepting or looking inside. 
This is useful when you want to establish a standard proxy and forwarding data. But this can also be useless when being used as a debug tool.

To work as a debug tool of HTTPS, the proxy itself should do two things: intercept the request and cheat the browser with a valid certificate,aka the man-in-the-middle(MITM) attack.

In order to have a browser-trusted certificate, we would sign certificates dynamically. The first thing to do is to generate a self-signed root CA and import to the system keychain. After trusting this CA, all child certs inherit from root CA can be naturally trusted by the browser. 

What this proxy do is to generate and replace a temporary cert for any domain if neccessary. Using it, we can intercept any requests for debug. BTW, this is also what the charlse/fiddler do when you check the enable_ssl_proxy in preference.

## Feature
* work as http or https proxy
* generate and intercept https requests for any domain without complaint by browser (after you trust its root CA)
* can be used globally or as a nodejs module 

## Usage
### step 0 - setup env

* install NodeJS
* install [openssl](http://wiki.openssl.org/index.php/Compilation_and_Installation) , i.e. the command ``openssl`` should be exposed to your shell

### step 1 - install

* ``npm install -g anyproxy`` , may need ``sudo``


### step 2 - generate a rootCA and trust it
* execute ``anyproxy --root`` ,follow the instructions on screen
* you will see some tip like *rootCA generated at : /usr/lib...* , just cd to that position, add the rootCA.crt file to your system keychain and trust. In OSX, you may do that by open the *crt file directly

### step 3 - start server

#### start with default settings
* ``anyproxy``

#### start with a specific port
* ``anyproxy --port 8001``

#### start a https proxy
* ``anyproxy --type https --host my.domain.com``
* the param ``host`` is required with https proxy and it should be kept exactly what it it when you config your browser. Otherwise, you may get some warning about security.

### others

#### work as a module
```
npm install anyproxy
```

```javascript
var proxy = require("anyproxy");

!proxy.isRootCAFileExists() && proxy.generateRootCA();
new proxy.proxyServer("http","8001", "localhost" ,"path/to/rule/file");

```

#### clear all the temperary certificates
* ``anyproxy --clear``

#### map file to local
* ``anyproxy --rule /path/to/ruleFile.js``
* actually ruleFile.js is a module for Nodejs
* a sample schema of ruls.js is as follows

```javascript
var rules = {
    "map" :[
        {
            "host"      :/./,            //regExp
            "path"      :/\/path\/test/, //regExp
            "localFile" :"",             //this file will be returned to user when host and path pattern both meets the request
            "localDir"  :"~/"            //find the file of same name in localdir. anyproxy will not read localDir settings unless localFile is falsy
        }
        ,{
            "host"      :/./,
            "path"      :/\.(png|gif|jpg|jpeg)/,
            "localFile" :"/Users/Stella/tmp/test.png",
            "localDir"  :"~/"
        }
    ]
    ,"httpsConfig":{
        "bypassAll" : false,  //by setting this to true, anyproxy will not intercept any https request
        "interceptDomains":[/www\.a\.com/,/www\.b\.com/] //by setting bypassAll:false, requests towards these domains will be intercepted, and try to meet the map rules above
    }
}

module.exports = rules;

```

## Contact
Author : Otto Mao, from Shanghai,China
ottomao@gmail.com

Please feel free to raise any issue about this project, or give me some advice on this poor english doc. :)
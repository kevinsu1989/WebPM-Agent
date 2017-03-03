"use strict";
if (!Date.prototype.toISOString) {
    Date.prototype.toISOString = function() {
        function pad(n) { return n < 10 ? '0' + n : n; }

        function ms(n) { return n < 10 ? '00' + n : n < 100 ? '0' + n : n }
        return this.getFullYear() + '-' +
            pad(this.getMonth() + 1) + '-' +
            pad(this.getDate()) + 'T' +
            pad(this.getHours()) + ':' +
            pad(this.getMinutes()) + ':' +
            pad(this.getSeconds()) + '.' +
            ms(this.getMilliseconds()) + 'Z';
    }
}

function createHAR(address, title, startTime, resources) {
    var entries = [];

    resources.forEach(function(resource) {
        var request = resource.request,
            startReply = resource.startReply,
            endReply = resource.endReply;

        if (!request || !startReply || !endReply) {
            return;
        }

        // Exclude Data URI from HAR file because
        // they aren't included in specification
        if (request.url.match(/(^data:image\/.*)/i)) {
            return;
        }

        entries.push({
            startedDateTime: request.time.toISOString(),
            time: endReply.time - request.time,
            request: {
                method: request.method,
                url: request.url,
                httpVersion: "HTTP/1.1",
                cookies: [],
                headers: request.headers,
                queryString: [],
                headersSize: -1,
                bodySize: -1
            },
            response: {
                status: endReply.status,
                statusText: endReply.statusText,
                httpVersion: "HTTP/1.1",
                cookies: [],
                headers: endReply.headers,
                redirectURL: "",
                headersSize: -1,
                bodySize: startReply.bodySize,
                content: {
                    size: startReply.bodySize,
                    mimeType: endReply.contentType
                }
            },
            cache: {},
            timings: {
                blocked: 0,
                dns: -1,
                connect: -1,
                send: 0,
                wait: startReply.time - request.time,
                receive: endReply.time - startReply.time,
                ssl: -1
            },
            pageref: address
        });
    });

    return {
        log: {
            version: '1.2',
            creator: {
                name: "PhantomJS",
                version: phantom.version.major + '.' + phantom.version.minor +
                    '.' + phantom.version.patch
            },
            pages: [{
                startedDateTime: startTime.toISOString(),
                id: address,
                title: title,
                pageTimings: {
                    onLoad: page.endTime - page.startTime
                }
            }],
            entries: entries
        }
    };
}

var page = require('webpage').create(),
    system = require('system');

if (system.args.length === 1) {
    console.log('Usage: netsniff.js <some URL>');
    phantom.exit(1);
} else {

    page.address = system.args[1];
    page.resources = [];

    page.onLoadStarted = function() {
        page.startTime = new Date();
    };

    page.onResourceRequested = function(req) {
        page.resources[req.id] = {
            request: req,
            startReply: null,
            endReply: null
        };
    };

    page.onResourceReceived = function(res) {
        if (res.stage === 'start') {
            page.resources[res.id].startReply = res;
        }
        if (res.stage === 'end') {
            page.resources[res.id].endReply = res;
        }
    };

    page.open(page.address, function(status) {
        var har;
        if (status !== 'success') {
            console.log('FAIL to load the address');
            phantom.exit(1);
        } else {
            page.endTime = new Date();
            page.title = page.evaluate(function() {
                return document.title;
            });
            har = createHAR(page.address, page.title, page.startTime, page.resources);
            console.log(JSON.stringify(har, undefined, 4));

            var jsdots = page.evaluate(function() {
                return window.__tj;
            });

            var _data = {
                har: har,
                jsdots: jsdots,
                html: page.content
            }

            console.log(JSON.stringify(_data, undefined, 4));

            phantom.exit();
        }
    });
}



var webpage = require('webpage'),
    args = require('system').args,
    fs = require('fs'),
    campaignId = args[1],
    pkg = JSON.parse(fs.read('./package.json'));

function snapshot(id, url, imagePath) {
    var page = webpage.create(),
        send, begin, save, end;
    page.viewportSize = { width: 1024, height: 800 };
    page.clipRect = { top: 0, left: 0, width: 1024, height: 800 };
    page.settings = {
        javascriptEnabled: false,
        loadImages: true,
        userAgent: 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.31 (KHTML, like Gecko) PhantomJS/1.9.0'
    };
    page.open(url, function(status) {
        var data;
        if (status === 'fail') {
            data = [
                'campaignId=',
                campaignId,
                '&url=',
                encodeURIComponent(url),
                '&id=',
                id,
                '&status=',
            ].join('');
            postPage.open('http://localhost:' + pkg.port + '/bridge', 'POST', data, function() {});
        } else {
            page.render(imagePath);
            var html = page.content;
            // callback NodeJS
            data = [
                'campaignId=',
                campaignId,
                '&html=',
                encodeURIComponent(html),
                '&url=',
                encodeURIComponent(url),
                '&image=',
                encodeURIComponent(imagePath),
                '&id=',
                id,
                '&status=',
            ].join('');
            postMan.post(data);
        }
        // release the memory
        page.close();
    });
}

var postMan = {
    postPage: null,
    posting: false,
    datas: [],
    len: 0,
    currentNum: 0,
    init: function(snapshot) {
        var postPage = webpage.create();
        postPage.customHeaders = {
            'secret': pkg.secret
        };
        postPage.open('http://localhost:' + pkg.port + '/bridge?campaignId=' + campaignId, function() {
            var urls = JSON.parse(postPage.plainText).urls,
                url;

            this.len = urls.length;

            if (this.len) {
                for (var i = this.len; i--;) {
                    url = urls[i];
                    snapshot(url.id, url.url, url.imagePath);
                }
            }
        });
        this.postPage = postPage;
    },
    post: function(data) {
        this.datas.push(data);
        if (!this.posting) {
            this.posting = true;
            this.fire();
        }
    },
    fire: function() {
        if (this.datas.length) {
            var data = this.datas.shift(),
                that = this;
            this.postPage.open('http://localhost:' + pkg.port + '/bridge', 'POST', data, function() {
                that.fire();
                // kill child process
                setTimeout(function() {
                    if (++this.currentNum === this.len) {
                        that.postPage.close();
                        phantom.exit();
                    }
                }, 500);
            });
        } else {
            this.posting = false;
        }
    }
};
postMan.init(snapshot);
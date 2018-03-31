/* global describe, it */
var assert = require("assert");

function run(values) {
    var context = {};
    delete require.cache[require.resolve("../../src/APIProxy/FileResource/checkScopes")];
    global.context = {
        setVariable: function (name, value) {
            context[name] = value;
        },

        getVariable: function (name) {
            return values[name];
        }
    };
    require("../../src/APIProxy/FileResource/checkScopes");
    return context;
}

// {"jti":"abc","sub":"xyz","scope":["MyApp.Read","MyApp.Write"], "client_id":"my-client-id",
// "cid":"my-client-id","grant_type":"authorization_code","user_id":"cba",
// "user_name":"test@example.com","email":"test@example.com","exp":9999999999,"zid":"my-zone-id"}
var token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS1pZC0xIn0.eyJqdGkiOiJhYmMiLCJzdWIiO" +
    "iJ4eXoiLCJzY29wZSI6WyJNeUFwcC5SZWFkIiwiTXlBcHAuV3JpdGUiXSwiY2xpZW50X2lkIjoibXktY2xpZW50LWlkIi" +
    "wiY2lkIjoibXktY2xpZW50LWlkIiwiZ3JhbnRfdHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsInVzZXJfaWQiOiJjYmE" +
    "iLCJ1c2VyX25hbWUiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiZXhwIjo5OTk5" +
    "OTk5OTk5LCJ6aWQiOiJteS16b25lLWlkIn0.FC6zbNZnIxsjTh13MeolVU1EGn7mOnpsDiqDiQkxoLHvF7PsyPwS_cYD5" +
    "4D72TF3I8rHZxZed0y60jDna_PHnVcZFRmRyrPqVH5r5X3RC21zDEsGZtfOPZ91A1_XX9G-ooKDZMgaI6wT8YOvmfavbh" +
    "RGSNIG4x-axWwZL9wTU_Q";

describe("checkScopes.js", function () {
    it("should not do anything for matching exact scope and path", function () {
        var result = run({
            "ro.spet.specs": JSON.stringify([{
                scope: "MyApp.Read",
                exact: true,
                patterns: [{ verb: "GET", url: "/something", exact: true }]
            }]),
            "ro.spet.token": token,
            "request.verb": "GET",
            "proxy.pathsuffix": "/something"
        });

        assert.deepEqual(result, {});
    });

    it("should not do anything for matching exact scope and path and wildcard method", function () {
        var result = run({
            "ro.spet.specs": JSON.stringify([{
                scope: "MyApp.Read",
                exact: true,
                patterns: [{ verb: "*", url: "/something", exact: true }]
            }]),
            "ro.spet.token": token,
            "request.verb": "POST",
            "proxy.pathsuffix": "/something"
        });

        assert.deepEqual(result, {});
    });

    it("should return forbidden for non-matching method", function () {
        var result = run({
            "ro.spet.specs": JSON.stringify([{
                scope: "MyApp.Read",
                exact: true,
                patterns: [{ verb: "GET", url: "/something", exact: true }]
            }]),
            "ro.spet.token": token,
            "request.verb": "POST",
            "proxy.pathsuffix": "/something/else"
        });

        assert.deepEqual(result, {
            "ro.spet.code": 403,
            "ro.spet.phrase": "Forbidden",
            "ro.spet.content": "Missing necessary scopes."
        });
    });

    it("should return forbidden for malformed token", function () {
        var result = run({
            "ro.spet.specs": "[]",
            "ro.spet.token": "adsdasdasda",
            "request.verb": "POST",
            "proxy.pathsuffix": "/something"
        });

        assert.deepEqual(result, {
            "ro.spet.code": 403,
            "ro.spet.phrase": "Forbidden",
            "ro.spet.content": "OAuth token missing or malformed."
        });
    });

    it("should return forbidden for missing token", function () {
        var result = run({
            "ro.spet.specs": "[]",
            "request.verb": "POST",
            "proxy.pathsuffix": "/something"
        });

        assert.deepEqual(result, {
            "ro.spet.code": 403,
            "ro.spet.phrase": "Forbidden",
            "ro.spet.content": "OAuth token missing or malformed."
        });
    });

    it("should return forbidden for non-matching exact path", function () {
        var result = run({
            "ro.spet.specs": JSON.stringify([{
                scope: "MyApp.Read",
                exact: true,
                patterns: [{ verb: "GET", url: "/something", exact: true }]
            }]),
            "ro.spet.token": token,
            "request.verb": "GET",
            "proxy.pathsuffix": "/something/else"
        });

        assert.deepEqual(result, {
            "ro.spet.code": 403,
            "ro.spet.phrase": "Forbidden",
            "ro.spet.content": "Missing necessary scopes."
        });
    });

    it("should return forbidden for non-matching exact scope", function () {
        var result = run({
            "ro.spet.specs": JSON.stringify([{
                scope: "MyApp.Execute",
                exact: true,
                patterns: [{ verb: "GET", url: "/something", exact: true }]
            }]),
            "ro.spet.token": token,
            "request.verb": "GET",
            "proxy.pathsuffix": "/something"
        });

        assert.deepEqual(result, {
            "ro.spet.code": 403,
            "ro.spet.phrase": "Forbidden",
            "ro.spet.content": "Missing necessary scopes."
        });
    });

    it("should not do anything for matching pattern scope", function () {
        var result = run({
            "ro.spet.specs": JSON.stringify([{
                scope: "MyApp.*",
                exact: false,
                patterns: [{ verb: "GET", url: "/something", exact: true }]
            }]),
            "ro.spet.token": token,
            "request.verb": "GET",
            "proxy.pathsuffix": "/something"
        });

        assert.deepEqual(result, {});
    });

    it("should not do anything for matching exact scope and pattern url", function () {
        var result = run({
            "ro.spet.specs": JSON.stringify([{
                scope: "MyApp.Read",
                exact: true,
                patterns: [{ verb: "GET", url: "^/something/.*$", exact: false }]
            }]),
            "ro.spet.token": token,
            "request.verb": "GET",
            "proxy.pathsuffix": "/something/else"
        });

        assert.deepEqual(result, {});
    });

    it("should not do anything for matching patten scope and pattern url", function () {
        var result = run({
            "ro.spet.specs": JSON.stringify([{
                scope: "MyApp.*",
                exact: false,
                patterns: [{ verb: "GET", url: "^/something/.*$", exact: false }]
            }]),
            "ro.spet.token": token,
            "request.verb": "GET",
            "proxy.pathsuffix": "/something/else"
        });

        assert.deepEqual(result, {});
    });

    it("should not do anything for matching exact scope, pattern url and multiple specs", function () {
        var result = run({
            "ro.spet.specs": JSON.stringify([{
                scope: "MyApp.Delete",
                exact: true,
                patterns: [{ verb: "DELETE", url: "^/something/.*$", exact: false }]
            }, {
                scope: "MyApp.Write",
                exact: true,
                patterns: [{ verb: "POST", url: "^/something/.*$", exact: false }]
            }, {
                scope: "MyApp.*",
                exact: false,
                patterns: [{ verb: "GET", url: "^/something/.*$", exact: false }]
            }]),
            "ro.spet.token": token,
            "request.verb": "POST",
            "proxy.pathsuffix": "/something/else"
        });

        assert.deepEqual(result, {});
    });
});

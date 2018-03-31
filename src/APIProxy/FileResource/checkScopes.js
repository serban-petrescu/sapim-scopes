(function (context) {

    // https://github.com/davidchambers/Base64.js/blob/master/base64.js
    function atob(input) {
        var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
        var str = String(input).replace(/[=]+$/, '');
        if (str.length % 4 == 1) {
            throw new Error("'atob' failed: The string to be decoded is not correctly encoded.");
        }
        for (
            var bc = 0, bs, buffer, idx = 0, output = '';
            buffer = str.charAt(idx++);
            ~buffer && (bs = bc % 4 ? bs * 64 + buffer : buffer,
                bc++ % 4) ? output += String.fromCharCode(255 & bs >> (-2 * bc & 6)) : 0
        ) {
            buffer = chars.indexOf(buffer);
        }
        return output;
    }

    function HttpException(statusCode, statusText, message) {
        this.statusCode = statusCode;
        this.statusText = statusText;
        this.message = (message || "");
    }
    HttpException.prototype = new Error();

    function getScopesFromToken(token) {
        try {
            return JSON.parse(atob(token.split(".")[1])).scope || [];
        } catch (e) {
            throw new HttpException(403, "Forbidden", "OAuth token missing or malformed.");
        }
    }

    function scopeExists(spec, scopes) {
        for (var i = 0; i < scopes.length; ++i) {
            if (spec.exact ? scopes[i] === spec.scope : scopes[i].match(spec.scope)) {
                return true;
            }
        }
        return false;
    }

    function patternMatches(pattern, verb, url) {
        return (pattern.verb === verb || pattern.verb === "*") &&
            (pattern.exact ? pattern.url === url : url.match(pattern.url));
    }

    function anyPatternMatches(patterns, verb, url) {
        for (var i = 0; i < patterns.length; ++i) {
            if (patternMatches(patterns[i], verb, url)) {
                return true;
            }
        }
        return false;
    }

    function checkSecurity(specs, scopes, verb, url) {
        for (var i = 0; i < specs.length; ++i) {
            if (scopeExists(specs[i], scopes) && anyPatternMatches(specs[i].patterns, verb, url)) {
                return true;
            }
        }
        return false;
    }

    try {
        var specs = JSON.parse(context.getVariable("ro.spet.specs")),
            scopes = getScopesFromToken(context.getVariable("ro.spet.token")),
            verb = context.getVariable("request.verb"),
            url = context.getVariable("proxy.pathsuffix") || context.getVariable("request.path");
        if (!checkSecurity(specs, scopes, verb, url)) {
            throw new HttpException(403, "Forbidden", "Missing necessary scopes.");
        }
    } catch (e) {
        context.setVariable("ro.spet.code", e.statusCode || 500);
        context.setVariable("ro.spet.phrase", e.statusText || "Internal Server Error");
        context.setVariable("ro.spet.content", e.message);
    }
})(context);
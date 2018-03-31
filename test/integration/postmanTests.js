require("sapim").default().getManifestUrl("proxy.yaml").then(function(url) {
    require("newman").run({
        collection: require("../../postman.json"),
        globals: {
            values: [{
                "key": "base-path",
                "value": url,
                "type": "text",
                "enabled": true
            }]
        },
        reporters: ["cli"]
    });
});
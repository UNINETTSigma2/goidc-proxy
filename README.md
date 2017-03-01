# OpenID Connect Proxy

The proxy is based on [coreos/go-oidc](https://github.com/coreos/go-oidc/) package. It supports simple proxying request based on authentication from any OpenID Connect providers. You can forward either `OAuth2 Accesstoken (oauth2)` or `JWT Token (jwt)` in `Authorization` header. The `OAuth2 Accesstoken`is the default option for sending to downstream target application. This is useful depending upon your target application configured under `proxy` section.

In addition to that it has support for two factor authentication which is primarily tested for [Dataporten](https://docs.dataporten.no/). Two factor can be enabled for selected users/groups or for all the users.

## Authentication with Dataporten

```
{
    "proxy": {
        "target": "https://httpbin.org"
    },
    "engine": {
        "client_id": "<client_id>",
        "client_secret": "<client_secret>",
        "issuer_url": "https://auth.dataporten.no",
        "redirect_url": "http://localhost:8888/oauth2/callback",
        "scopes": "userid",
        "signkey": "testtesttesttest",
        "groups_endpoint": "",
        "token_type": "oauth2",
        "jwt_token_issuer": "https://jwt.example.no",
        "twofactor": {
            "all": false,
            "redirect_on_response": false,
            "principals": "",
            "acr_values": "",
        },
        "logging": {
            "level": "info"
        }
    },
    "server": {
        "port": 8888,
        "health_port": 1337,
        "cert": "cert.pem",
        "key": "key.pem",
        "ssl": false,
        "secure_cookie": false
    }
}
```

You need to copy the client-id and client-sercret from [Dataporten Dashboard](https://dashboard.dataporten.no/). Also make sure you have the redirect_url set accordingly as well as other details.

## Authentication with Google OpenID Connect

The configuration file for using Google as [OpenID provider](https://developers.google.com/identity/protocols/OpenIDConnect)

```
{
    "proxy": {
        "target": "https://httpbin.org"
    },
    "engine": {
        "client_id": "<client-id>",
        "client_secret": "<client-sercret>",
        "issuer_url": "https://accounts.google.com",
        "redirect_url": "http://localhost:8888/oauth2/callback",
        "scopes": "email",
        "signkey": "testtesttesttest",
        "groups_endpoint": "",
        "token_type": "oauth2",
        "jwt_token_issuer": "https://jwt.example.no",
        "twofactor": {
            "all": false,
            "redirect_on_response": false,
            "principals": "",
            "acr_values": "",
        },
        "logging": {
            "level": "debug"
        }
    },
    "server": {
        "port": 8888,
        "health_port": 1337,
        "cert": "cert.pem",
        "key": "key.pem",
        "ssl": false,
        "secure_cookie": false
    }
}
```

You need to copy the client-id and client-sercret from Google API console. Also make sure you have the redirect_url set accordingly as well as other details.
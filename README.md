#  HTTP Authentication
HTTP Access Authentication

## Authentication Flow
![Basic Flow](https://user-images.githubusercontent.com/58973699/73819423-75c6a380-482a-11ea-97ea-d2820fee923d.png)

Firstly, HTTP client makes a request to the web server. Request method can be any method not just GET. The server responds to a client with:
 - 401 (Unauthorized) response status and provides information on how to authorize with a *WWW-Authenticate* response header containing at least one challenge. 
 - 407 (Proxy Authentication Required) response status code and provides information on how to authorize with a *Proxy-Authenticate* response header contains at least one challenge.

A client that wants to authenticate itself with a server can then do so by including an *Authorization* request header field with the credentials.  Usually a client will present a password prompt to the user and will then issue the request including the correct *Authorization* header.

**WWW-Authenticate** & **Proxy-Authenticate headers**
```
WWW-Authenticate: <authentication-schemes> realm=<realm> ..
Proxy-Authenticate: <authentication-schemes> realm=<realm> ..
```
**Authorization** &  **Proxy-Authorization headers**
```
Authorization: <authentication-schemes> <credentials>
Proxy-Authorization: <authentication-schemes> <credentials>
```
## Authentication schemes
The general HTTP authentication is used by several authentication schemes. Schemes can differ in security strength and in their availability in client or server software. Common authentication schemes include:

* Basic [RFC2617](https://tools.ietf.org/html/rfc2617)
* Digest [RFC2617](https://tools.ietf.org/html/rfc2617)
* Bearer (will be added later)

### Basic Authentication Scheme

* Challenge: ``` Basic realm=<realm>```
* Credentials: ```Basic <basic-credentials>```

with : ```credentials = base64(username + ":" + password)```


### Digest Authentication Scheme

* Challenge: ``` Digest (realm|[domain]|nonce|[opaque]|[stale]|[algorithm]|[qop]|[auth-param])```
* Credentials: ```Digest (username|realm|nonce|uri|response|algorithm|cnonce|[opaque]|[qop]|nc|[auth-param])```

With:
`The algorithm can be MD5, MD5-sess or unspecified.`
* H(data) = MD5(data)
* KD(secret, data) = H(concat(secret:data))


* A1:
    * A1 = username:realm:password                          `algorithm="MD5" | algorithm is unspecified`
    * A1 = H(username:realm:password):nonce:cnonce          `algorithm=<algorithm>-sess`
    
* A2:                                     
    * A2 = method:uri:H(entity-body)                        `qop="auth-int"`    
    * A2 = method:uri                                       `qop="auth" | qop is unspecified`

* response:
    * response = KD(H(A1),nonce:nc:cnonce:qop:H(A2))        `qop="auth" | qop="auth-int"`
    * response = KD(H(A1),nonce:H(A2))                      `qop is unspecified`

## Demonstration
* Start Server: ```python auth_server.py```
* Start Client: ```python client.py``` or Browser: Chrome/Firefox/Edge or Postman

## Note:
SIP challenge-based mechanism for authentication that is based on authentication in HTTP

## Reference:
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
* https://tools.ietf.org/html/rfc2617

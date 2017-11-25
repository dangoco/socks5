SOCKS v4/v4a/v5 server implementation with user/pass authentication node.js
=============================================================================

A simple SOCKS v5/v4/v4a server implementation and demo proxy.

You can run it easily as:

```
  node proxy.js [options]
```

This will create a proxy defaults at `127.0.0.1:8888`.

`options`:see `node proxy.js --help`

You can use this as a good starting point for writing a proxy or a tunnel!

### Install

```
npm install socks5server
```

### Use the server in your project

```
const socks5server=require('socks5server');

var server=socks5server.createServer();
//or
var server=new socks5server.socksServer();
```
The `proxy.js` is a simple demo of the server.

### Implementations

✅:OK
❌:not implemented
❓:i don't kown

#### Socks4
* user 					✅

#### Socks4a
* DNS 					✅

#### Socks5
* address
	* ipv4				✅
	* ipv6				✅
	* domain name		✅

* auth methods
	* no auth 			✅
	* userpass 			✅
	* GSSAPI 			❌
	* iana assigned		❌
	* private methods	✅

* CMD
	* connect			✅
	* udp				❌ (hope if someone can help)
	* bind 				❌
	
socks replsy not completed

### License

(The MIT License)

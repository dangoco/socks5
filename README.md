SOCKS v4/v4a/v5 server implementation with user/pass authentication node.js
=============================================================================

A simple SOCKS v5/v4/v4a server implementation and demo proxy.

You can run it easily as:

```
node proxy.js [options]
```

This will create a proxy defaults at `127.0.0.1:1080`.

`options`:see `node proxy.js --help`


### Install

```
npm install socks5server
```

### Use the server in your project

```javascript
const socks5server=require('socks5server');

var server=socks5server.createServer();
//or
var server=new socks5server.socksServer();

server
.on('tcp',(socket, port, address, CMD_REPLY)=>{
	//do sth with the tcp proxy request
}).on('udp',(socket, clientPort, clientAddress, CMD_REPLY)=>{
	//do sth with the udp proxy request
}).on('error', function (e) {
	console.error('SERVER ERROR: %j', e);
}).on('client_error',(socket,e)=>{
	console.error('  [client error]',`${net.isIP(socket.targetAddress)?'':'('+socket.targetAddress+')'} ${socket.remoteAddress}:${socket.targetPort}`,e.message);
}).on('socks_error',(socket,e)=>{
	console.error('  [socks error]',`${net.isIP(socket.targetAddress)?'':'('+(socket.targetAddress||"unknown")+')'} ${socket.remoteAddress||"unknown"}}:${socket.targetPort||"unknown"}`,e);
}).listen(1080, "127.0.0.1");

/*
CMD_REPLY(reply code,addr,port)
see https://www.ietf.org/rfc/rfc1928.txt "6 Replies"@page5 for details
*/
```
The `proxy.js` is a simple demo of the server.

### Implementations

✅:OK
❌:not implemented
❓:i don't kown

#### Socks4
* ❓ 					

#### Socks4a
* ❓

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
	* private methods	✅ (use as a module)

* CMD
	* connect			✅
	* udp				✅ (maybe usable)
		* fragment		❌ (no plan on it)
	* bind 				❌

*I mainly modified the socks5 part and not sure if socks4 has been completely implemented.*

RFC:
* [socks5](https://www.ietf.org/rfc/rfc1928.txt)

### License

(The MIT License)

'use strict'

const net = require('net'),
	util = require('util'),
	DNS = require('dns'),
	SOCKS_VERSION5 = 5,
	SOCKS_VERSION4 = 4,
/*
 * Authentication methods
 ************************
 * o  X'00' NO AUTHENTICATION REQUIRED
 * o  X'01' GSSAPI
 * o  X'02' USERNAME/PASSWORD
 * o  X'03' to X'7F' IANA ASSIGNED
 * o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
 * o  X'FF' NO ACCEPTABLE METHODS
 */
	AUTHENTICATION = {
		NOAUTH: 0x00,
		GSSAPI: 0x01,
		USERPASS: 0x02,
		NONE: 0xFF
	},
/*
 * o  CMD
 *    o  CONNECT X'01'
 *    o  BIND X'02'
 *    o  UDP ASSOCIATE X'03'
 */
	REQUEST_CMD = {
		CONNECT: 0x01,
		BIND: 0x02,
		UDP_ASSOCIATE: 0x03
	},
/*
 * o  ATYP   address type of following address
 *    o  IP V4 address: X'01'
 *    o  DOMAINNAME: X'03'
 *    o  IP V6 address: X'04'
 */
	ATYP = {
		IP_V4: 0x01,
		DNS: 0x03,
		IP_V6: 0x04
	};



const _005B=Buffer.from([0x00, 0x5b]),
	_0101=Buffer.from([0x01, 0x01]),
	_0501=Buffer.from([0x05, 0x01]),
	_0100=Buffer.from([0x01, 0x00]);


const	Address = {
	read: function (buffer, offset) {
		if (buffer[offset] == ATYP.IP_V4) {
			return util.format('%s.%s.%s.%s', buffer[offset+1], buffer[offset+2], buffer[offset+3], buffer[offset+4]);
		} else if (buffer[offset] == ATYP.DNS) {
			return buffer.toString('utf8', offset+2, offset+2+buffer[offset+1]);
		} else if (buffer[offset] == ATYP.IP_V6) {
			return buffer.slice(buffer[offset+1], buffer[offset+1+16]);
		}
	},
	sizeOf: function(buffer, offset) {
		if (buffer[offset] == ATYP.IP_V4) {
			return 4;
		} else if (buffer[offset] == ATYP.DNS) {
			return buffer[offset+1];
		} else if (buffer[offset] == ATYP.IP_V6) {
			return 16;
		}
	}
},
Port = {
	read: function (buffer, offset) {
		if (buffer[offset] == ATYP.IP_V4) {
			return buffer.readUInt16BE(8);
		} else if (buffer[offset] == ATYP.DNS) {
			return buffer.readUInt16BE(5+buffer[offset+1]);
		} else if (buffer[offset] == ATYP.IP_V6) {
			return buffer.readUInt16BE(20);
		}
	},
};

class socksServer extends net.Server{
	constructor(options,connectionListener){
		super(options,connectionListener);
		// this._proxyReady5=this._proxyReady5.bind(this);
		this.enabledVersion=new Set([SOCKS_VERSION5,SOCKS_VERSION4]);
		this.socks5={
			authMethodsList:new Set([AUTHENTICATION.NOAUTH]),
			authConf:{
				userpass:new Map(),
			},
			authFunc:{
				[AUTHENTICATION.USERPASS]:this._socks5UserPassAuth.bind(this),
				[AUTHENTICATION.NOAUTH]:this._socks5NoAuth.bind(this),
			}
		};
		this.on('connection', socket=>{
			//socket._socksServer=this;
			socket.on('error',e=>{
				this.emit('socket_error',socket,e);
			}).once('data',chunk=>{
				this.handshake(socket,chunk);
			}).on('socks_error',e=>{
				this.emit('socks_error',socket,e);
			});
		});
	}
	setSocks5AuthFunc(method,func){//method is the number
		if(typeof func !== 'function' || typeof method !== 'number')
			throw(new TypeError('Invalid arguments'));
		this.socks5.authFunc[method]=func;
	}
	setSocks5AuthMethods(list){
		if(!Array.isArray(list))
			throw(new TypeError('Not an Array'));
		this.socks5.authMethodsList=new Set(list);
	}
	deleteSocks5AuthMethod(method){//method is the number
		return this.socks5.authMethodsList.delete(method);
	}
	setSocks5UserPass(user,pass){
		if(typeof user !== 'string' || typeof pass !== 'string')
			throw(new TypeError('Invalid username or password'));
		this.socks5.authConf.userpass.set(user,pass);
		let methodList=this.socks5.authMethodsList;
		if(!methodList.has(AUTHENTICATION.USERPASS)){
			methodList.add(AUTHENTICATION.USERPASS);
		}
		if(methodList.has(AUTHENTICATION.NOAUTH)){
			methodList.delete(AUTHENTICATION.NOAUTH);
		}
	}
	deleteSocks5UserPass(user){
		return this.socks5.authConf.userpass.delete(user);
	}
	handshake(socket,chunk){
		if(!this.enabledVersion.has(chunk[0])){
			socket.end();
			socket.emit('socks_error',`handshake: not enabled version: ${chunk[0]}`);
		}
		if (chunk[0] == SOCKS_VERSION5) {
			socket.socksVersion = SOCKS_VERSION5;
			this._handshake5(socket,chunk);
		} else if (chunk[0] == SOCKS_VERSION4) {
			socket.socksVersion = SOCKS_VERSION4;
			this._handshake4(socket,chunk);
		} else {
			socket.end();
			socket.emit('socks_error',`handshake: wrong socks version: ${chunk[0]}`);
		}
	}
	_handshake4(socket,chunk){// SOCKS4/4a
		let cmd = chunk[1],
			address,
			port,
			uid;

		port = chunk.readUInt16BE(2);

		// SOCKS4a
		if ((chunk[4] === 0 && chunk[5] === chunk[6] === 0) && (chunk[7] !== 0)) {
			var it = 0;

			uid = '';
			for (it = 0; it < 1024; it++) {
				uid += chunk[8 + it];
				if (chunk[8 + it] === 0x00)
					break;
			}
			address = '';
			if (chunk[8 + it] === 0x00) {
				for (it++; it < 2048; it++) {
					address += chunk[8 + it];
					if (chunk[8 + it] === 0x00)
						break;
				}
			}
			if (chunk[8 + it] === 0x00) {
				// DNS lookup
				DNS.lookup(address,(err, ip, family)=>{
					if (err) {
						socket.end(_005B);
						socket.emit('socks_error',err);
						return;
					} else {
						socket.socksAddress = ip;
						socket.socksPort = port;
						socket.socksUid = uid;

						if (cmd == REQUEST_CMD.CONNECT) {
							socket.request = chunk;
							this.emit('socket',socket, port, ip, 'tcp', proxyReady4.bind(socket));
						} else {
							socket.end(_005B);
							return;
						}
					}
				});
			} else {
				socket.end(_005B);
				return;
			}
		} else {
			// SOCKS4
			address = util.format('%s.%s.%s.%s', chunk[4], chunk[5], chunk[6], chunk[7]);

			uid = '';
			for (it = 0; it < 1024; it++) {
				uid += chunk[8 + it];
				if (chunk[8 + it] == 0x00)
					break;
			}

			socket.socksAddress = address;
			socket.socksPort = port;
			socket.socksUid = uid;

			if (cmd == REQUEST_CMD.CONNECT) {
				socket.request = chunk;
				this.emit('socket',socket, port, address, 'tcp', proxyReady4.bind(socket));
			} else {
				socket.end(_005B);
				return;
			}
		}
	}
	_handshake5(socket,chunk){
		let method_count = 0;

		// Number of authentication methods
		method_count = chunk[1];

		if(chunk.byteLength<method_count+2){
			socket.end();
			socket.emit('socks_error','socks5 handshake error: too short chunk');
			return;
		}

		let availableAuthMethods=[];
		// i starts on 2, since we've read chunk 0 & 1 already
		for (let i=2; i < method_count + 2; i++) {
			if(this.socks5.authMethodsList.has(chunk[i])){
				availableAuthMethods.push(chunk[i]);
			}
		}

		let resp = Buffer.from([
					SOCKS_VERSION5,//response version 5
					availableAuthMethods[0]//select the first auth method
				]);
		let authFunc=this.socks5.authFunc[resp[1]];

		if(availableAuthMethods.length===0 || !authFunc){//no available auth method
			resp[1] = AUTHENTICATION.NONE;
			socket.end(resp);
			socket.emit('socks_error','unsuported authentication method');
			return;
		}

		// auth
		socket.once('data',chunk=>{
			authFunc.call(this,socket,chunk);
		});

		socket.write(resp);
	}
	_socks5UserPassAuth(socket,chunk){
		let username,password;
		// Wrong version!
		if (chunk[0] !== 1) { // MUST be 1
			socket.end(_0101);
			socket.emit('socks_error',`socks5 handleAuthRequest: wrong socks version: ${chunk[0]}`);
			return;
		}
	 
		try {
			let na = [],pa=[],ni,pi;
			for (ni=2;ni<(2+chunk[1]);ni++) na.push(chunk[ni]);username = Buffer.from(na).toString('utf8');
			for (pi=ni+1;pi<(ni+1+chunk[ni]);pi++) pa.push(chunk[pi]);password = Buffer.from(pa).toString('utf8');       
		} catch (e) {
			socket.end(_0101);
			socket.emit('socks_error',`socks5 handleAuthRequest: username/password ${e}`);
			return;
		}

		// check user:pass
		let users=this.socks5.authConf.userpass;
		if (users && users.has(username) && users.get(username)===password) {
			socket.once('data',chunk=>{
				this._socks5HandleRequest(socket,chunk);
			});
			socket.write(_0100);
		} else {
			socket.end(_0101);
			socket.emit('socks_error',`socks5 handleConnRequest: wrong socks version: ${chunk[0]}`);
			return;
		}
	}
	_socks5NoAuth(socket,chunk){
		this._socks5HandleRequest(socket,chunk);
	}
	_socks5HandleRequest(socket,chunk){
		let cmd=chunk[1],
			address,
			port,
			offset=3;
		/* if (chunk[2] == 0x00) {
			this.end(util.format('%d%d', 0x05, 0x01));
			errorLog('socks5 handleConnRequest: Mangled request. Reserved field is not null: %d', chunk[offset]);
			return;
		} */
		try {
			address = Address.read(chunk, 3);
			port = Port.read(chunk, 3);
		} catch (e) {
			socket.end();
			socket.emit('socks_error',e);
			return;
		}

		if (cmd === REQUEST_CMD.CONNECT) {
			socket.request = chunk;
			this.emit('socket',socket, port, address, 'tcp', proxyReady5.bind(socket));
		} else {
			socket.end(_0501);
			return;
		}
	}
}
socksServer.AUTHENTICATION=AUTHENTICATION;

function proxyReady5() {//'this' is the socket
	// creating response
	let resp = Buffer.allocUnsafe(this.request.length);
	this.request.copy(resp);
	// rewrite response header
	resp[0] = SOCKS_VERSION5;
	resp[1] = 0x00;
	resp[2] = 0x00;
	
	this.write(resp);
}

function proxyReady4() {//'this' is the socket
	// creating response
	let resp = Buffer.allocUnsafe(8);
	
	// write response header
	resp[0] = 0x00;
	resp[1] = 0x5a;
	
	// port
	resp.writeUInt16BE(this.socksPort, 2);
	
	// ip
	let ips = this.socksAddress.split('.');
	resp.writeUInt8(parseInt(ips[0]), 4);
	resp.writeUInt8(parseInt(ips[1]), 5);
	resp.writeUInt8(parseInt(ips[2]), 6);
	resp.writeUInt8(parseInt(ips[3]), 7);
	
	this.write(resp);
}



function createSocksServer() {
	return new socksServer();
}


module.exports = {
	createServer: createSocksServer,
	socksServer,
};

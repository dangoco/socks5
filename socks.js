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

function createSocksServer(userpassObj) {
	let socksServer = net.createServer();
	socksServer.users=userpassObj;
	socksServer.on('connection', function(socket) {
		socket._socksServer=socksServer;
		socket.once('data',chunk=>{
			handshake.call(socket,chunk);
		});
	});
	return socksServer;
}


function handshake(chunk) {//'this' is the socket
	// SOCKS Version 4/5 is the only support version
	if (chunk[0] == SOCKS_VERSION5) {
		this.socksVersion = SOCKS_VERSION5;
		handshake5.call(this,chunk);
	} else if (chunk[0] == SOCKS_VERSION4) {
		this.socksVersion = SOCKS_VERSION4;
		handshake4.call(this,chunk);
	} else {
		this.destroy(new Error(`handshake: wrong socks version: ${chunk[0]}`));
	}
}

// SOCKS5
function handshake5(chunk) {//'this' is the socket
	let method_count = 0;

	// SOCKS Version 5 is the only support version
	if (chunk[0] != SOCKS_VERSION5) {
		this.destroy(new Error(`socks5 handshake: wrong socks version: ${chunk[0]}`));
		return;
	}
	// Number of authentication methods
	method_count = chunk[1];

	this.auth_methods = [];
	// i starts on 2, since we've read chunk 0 & 1 already
	for (let i=2; i < method_count + 2; i++) {
		this.auth_methods.push(chunk[i]);
	}

	let resp = Buffer.alloc(2);
	resp[0] = 0x05;

	// user/pass auth
	if (this._socksServer.users) {
		if (this.auth_methods.indexOf(AUTHENTICATION.USERPASS) > -1) {
			this.once('data',chunk=>{
				handleAuthRequest.call(this,chunk);
			});
			resp[1] = AUTHENTICATION.USERPASS;
			this.write(resp);
		} else {
			resp[1] = 0xFF;
			this.end(resp);
			this.emit('error','unsuported authentication method');
		}
	} else
		// NO Auth
		if (this.auth_methods.indexOf(AUTHENTICATION.NOAUTH) > -1) {
			this.once('data',chunk=>{
				handleConnRequest.call(this,chunk);
			});
			resp[1] = AUTHENTICATION.NOAUTH;
			this.write(resp);
		} else {
			resp[1] = 0xFF;
			this.end(resp);
			this.emit('error','unsuported authentication method');
		}
}

const _005B=Buffer.from([0x00, 0x5b]),
	_0101=Buffer.from([0x01, 0x01]),
	_0501=Buffer.from([0x05, 0x01]),
	_0100=Buffer.from([0x01, 0x00]);


// SOCKS4/4a
function handshake4(chunk) {//'this' is the socket
	let cmd = chunk[1],
		address,
		port,
		uid;

	// Wrong version!
	if (chunk[0] !== SOCKS_VERSION4) {
		this.end(_005B);
		this.emit('error',`socks4 handleConnRequest: wrong socks version: ${chunk[0]}`);
		return;
	}
	port = chunk.readUInt16BE(2);

	// SOCKS4a
	if ((chunk[4] === 0 && chunk[5] === chunk[6] === 0) && (chunk[7] !== 0)) {
		let it = 0;

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
			DNS.lookup(address, function (err, ip, family) {
				if (err) {
					this.end(_005B);
					this.emit('error',err);
					return;
				} else {
					this.socksAddress = ip;
					this.socksPort = port;
					this.socksUid = uid;

					if (cmd == REQUEST_CMD.CONNECT) {
						this.request = chunk;
						this._socksServer.emit('socket',this, port, ip, proxyReady4.bind(this));
					} else {
						this.end(_005B);
						return;
					}
				}
			});
		} else {
			this.end(_005B);
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

		this.socksAddress = address;
		this.socksPort = port;
		this.socksUid = uid;

		if (cmd == REQUEST_CMD.CONNECT) {
			this.request = chunk;
			this._socksServer.emit('socket',this, port, address, proxyReady4.bind(this));
		} else {
			this.end(_005B);
			return;
		}
	}
}

function handleAuthRequest(chunk) {//'this' is the socket
	let username,
		password;
	// Wrong version!
	if (chunk[0] !== 1) { // MUST be 1
		this.end(_0101);
		this.emit('error',`socks5 handleAuthRequest: wrong socks version: ${chunk[0]}`);
		return;
	}
 
	try {
		let na = [],pa=[],ni,pi;
		for (ni=   2;ni<(2+chunk[1]);    ni++) na.push(chunk[ni]);username = Buffer.from(na).toString('utf8');
		for (pi=ni+1;pi<(ni+1+chunk[ni]);pi++) pa.push(chunk[pi]);password = Buffer.from(pa).toString('utf8');       
	} catch (e) {
		this.end(_0101);
		this.emit('error',`socks5 handleAuthRequest: username/password ${e}`);
		return;
	}

	// check user:pass
	let users=this._socksServer.users;
	if (users && (username in users) && users[username]===password) {
		this.once('data',chunk=>{
			handleConnRequest.call(this,chunk);
		});
		this.write(_0100);
	} else {
		this.end(_0101);
		this.emit('error',`socks5 handleConnRequest: wrong socks version: ${chunk[0]}`);
		return;
	}
}

function handleConnRequest(chunk) {//'this' is the socket
	let cmd=chunk[1],
		address,
		port,
		offset=3;
	// Wrong version!
	if (chunk[0] !== SOCKS_VERSION5) {
		this.end(_0501);
		this.emit('error',`socks5 handleConnRequest: wrong socks version: ${chunk[0]}`);
		return;
	} /* else if (chunk[2] == 0x00) {
		this.end(util.format('%d%d', 0x05, 0x01));
		errorLog('socks5 handleConnRequest: Mangled request. Reserved field is not null: %d', chunk[offset]);
		return;
	} */
	try {
		address = Address.read(chunk, 3);
		port = Port.read(chunk, 3);
	} catch (e) {
		this.destroy(e);
		return;
	}

	if (cmd == REQUEST_CMD.CONNECT) {
		this.request = chunk;
		this._socksServer.emit('socket',this, port, address, proxyReady5.bind(this));
	} else {
		this.end(_0501);
		return;
	}
}

function proxyReady5() {
	// creating response
	let resp = Buffer.allocUnsafe(this.request.length);
	this.request.copy(resp);
	// rewrite response header
	resp[0] = SOCKS_VERSION5;
	resp[1] = 0x00;
	resp[2] = 0x00;
	
	this.write(resp);
}

function proxyReady4() {
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

module.exports = {
	createServer: createSocksServer
};

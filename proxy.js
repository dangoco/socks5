
var net = require('net'),
	dgram = require('dgram'),
	{
		createServer,
		Address,
		Port,
		UDPRelay,
	} = require('./socks.js');
var commander = require('commander');
	
commander
	.usage('[options]')
	.option('-u, --user [value]', 'set a user:pass format user')
	.option('-H, --host [value]', 'host to listen,defaults to 127.0.0.1')
	.option('-P, --port <n>', 'port to listen,defaults to 1080',/^\d+$/i)
	.option('--localAddress [value]', 'local address to establish the connection')
	.option('--localPort [value]', 'local port to establish the connection')
	.parse(process.argv);

// Create server
// The server accepts SOCKS connections. This particular server acts as a proxy.
var HOST=commander.host||'127.0.0.1',
	PORT=commander.port||'1080',
	server = createServer();

console.log('server starting at ',HOST,':',PORT);

if(commander.user){
	let u=commander.user.split(":");
	server.setSocks5UserPass(u[0],u[1]);
	console.log('user ',commander.user);
}

/*
tcp request relay
directly connect the target and source
*/
function relayTCP(socket, port, address, CMD_REPLY){
	let proxy = net.createConnection({
		port:port, 
		host:address,
		localAddress:commander.localAddress||undefined,
		localPort:commander.localPort||undefined
	},CMD_REPLY);
	proxy.targetAddress=address;
	proxy.targetPort=port;
	proxy.on('connect',()=>{
		CMD_REPLY(0x00,proxy.localAddress,proxy.localPort);
		console.log('[TCP]',`${socket.remoteAddress}:${socket.remotePort} ==> ${net.isIP(address)?'':'('+address+')'} ${proxy.remoteAddress}:${proxy.remotePort}`);
		proxy.pipe(socket);
		socket.pipe(proxy);
	}).on('error',e=>{
		CMD_REPLY(0x01);
		console.error('	[TCP proxy error]',`${proxy.targetAddress}:${proxy.targetPort}`,e.message);
	});
	 
	socket.on('close',e=>{
		let msg='';
		if(socket.remoteAddress)
			msg+=`${socket.remoteAddress}:${socket.remotePort} ==> `;
		if(proxy.remoteAddress){
			msg+=`${net.isIP(address)?'':'('+address+')'} ${proxy.remoteAddress}:${proxy.remotePort}`;
		}else{
			msg+=`${address}:${port}`;
		}
		console.log('  [TCP closed]',msg);
	});
}

/*
udp request relay
send udp msgs to each other
*/
function relayUDP(socket, port, address, CMD_REPLY){
	console.log('[UDP]',`${socket.remoteAddress}`);
	let relay=new UDPRelay(socket, port, address, CMD_REPLY);

	relay.on('datagram',packet=>{//client to target forward
		relay.relaySocket.send(packet.data,packet.port,packet.address,err=>{
			if(err)server.emit('proxy_error',proxy,'UDP to remote error',err);
		});
	});
	relay.relaySocket.on('message',(msg,info)=>{//target to client forward
		if(!relay.usedClientAddress)return;//ignore if client address is unknown
		if(info.address===relay.usedClientAddress && info.port===relay.usedClientPort)return;//ignore client message
		relay.relaySocket.send(Buffer.concat([relay.headCache,msg]),relay.usedClientPort,relay.usedClientAddress,err=>{
			if(err)console.error('	[UDP proxy error]',err.message);
		});
	}).once('close',()=>{
		console.log('  [UDP closed]',socket.remoteAddress);
	});


}


//the socks server
server
.on('tcp',relayTCP)
.on('udp',relayUDP)
.on('error', function (e) {
	console.error('SERVER ERROR: %j', e);
	if(e.code == 'EADDRINUSE') {
		console.log('Address in use, retrying in 10 seconds...');
		setTimeout(function () {
			console.log('Reconnecting to %s:%s', HOST, PORT);
			server.close();
			server.listen(PORT, HOST);
		}, 10000);
	}
}).on('client_error',(socket,e)=>{
	console.error('  [client error]',`${net.isIP(socket.targetAddress)?'':'('+socket.targetAddress+')'} ${socket.remoteAddress}:${socket.targetPort}`,e.message);
}).on('socks_error',(socket,e)=>{
	console.error('  [socks error]',`${net.isIP(socket.targetAddress)?'':'('+(socket.targetAddress||"unknown")+')'} ${socket.remoteAddress||"unknown"}}:${socket.targetPort||"unknown"}`,e);
}).listen(PORT, HOST);


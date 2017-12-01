
var net = require('net'),
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
	.option('-P, --port <n>', 'host to listen,defaults to 1080',/^\d+$/i)
	.option('-L, --localAddress [value]', 'local assress to send the connection')
	.parse(process.argv);

// Create server
// The server accepts SOCKS connections. This particular server acts as a proxy.
var HOST=commander.host||'127.0.0.1',
	PORT=commander.port||'8888',
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
function TCPRelay(socket, port, address, CMD_REPLY){
	let proxy = net.createConnection({port:port, host:address,localAddress:commander.localAddress||undefined}, CMD_REPLY);
	proxy.targetAddress=address;
	proxy.targetPort=port;
	proxy.on('connect',()=>{
		CMD_REPLY();
		console.log('[TCP]',`${socket.remoteAddress}:${socket.remotePort} ==> ${net.isIP(address)?'':'('+address+')'} ${proxy.remoteAddress}:${proxy.remotePort}`);
		proxy.pipe(socket);
		socket.pipe(proxy);
	}).on('error',e=>{
		CMD_REPLY(0x01);
		server.emit('proxy_error',proxy,e);
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
		console.log('  [proxy closed]',msg);
	});
}





server.on('tcp',TCPRelay)
.on('udp',(socket, port, address, CMD_REPLY)=>{
	console.log('[UDP]',`${socket.remoteAddress}:${socket.remotePort} ==> ${address}:${port}`);
	new UDPRelay(socket, port, address, CMD_REPLY);
}).on('error', function (e) {
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
	console.error('  [socks error]',`${net.isIP(socket.targetAddress)?'':'('+socket.targetAddress+')'} ${socket.remoteAddress}:${socket.targetPort}`,e.message);
}).on('proxy_error',(proxy,e)=>{
	console.error('  [proxy error]',`${proxy.targetAddress}:${proxy.targetPort}`,e.message);
}).listen(PORT, HOST);


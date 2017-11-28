
var net = require('net'),
	{
		createServer,
		Address,
		Port,
		UDPRelay,
	} = require('./socks.js'),
	info = console.log.bind(console),
	dgram = require('dgram'),
	dns = require('dns');
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

info('server started at ',HOST,':',PORT);

if(commander.user){
	let u=commander.user.split(":");
	server.setSocks5UserPass(u[0],u[1]);
	info('user ',commander.user);
}

/*
tcp request relay
directly connect the target and source
*/
function TCPRelay(socket, port, address, CMD_REPLY){
	let proxy = net.createConnection({port:port, host:address,localAddress:commander.localAddress||undefined}, CMD_REPLY);
	proxy.on('connect',()=>{
		CMD_REPLY();
		info(`[TCP] ${socket.remoteAddress}:${socket.remotePort} ==> ${net.isIP(address)?address:address+'('+proxy.remoteAddress+')'}:${proxy.remotePort}`);
		proxy.pipe(socket);
		socket.pipe(proxy);
		proxy.on('error',e=>{
			console.error('connection error:',e);
			server.emit('connection_error',e);
		});
	}).on('error',e=>{
		CMD_REPLY(0x01);
		console.error('proxy error:',e.message);
	});
	 
	socket.on('close',e=>{
		if(!e)
			console.log('Proxy closed',`${address}:${port}`);
		else{
			console.log('Proxy failed',`${address}:${port}`);
		}
	});
}





server.on('tcp',TCPRelay)
.on('udp',(socket, port, address, CMD_REPLY)=>{
	new UDPRelay(socket, port, address, CMD_REPLY);
})
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
}).on('socket_error',(socket,e)=>{
	console.error('socket error:',e);
}).on('socks_error',(socket,e)=>{
	console.error('socks error:',e);
}).listen(PORT, HOST);


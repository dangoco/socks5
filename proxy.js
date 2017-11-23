
var net = require('net'),
	socks = require('./socks.js'),
	info = console.log.bind(console);
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
	server = socks.createServer();

info('server started at ',HOST,':',PORT);

if(commander.user){
	let u=commander.user.split(":");
	server.setSocks5UserPass(u[0],u[1]);
	info('user ',commander.user);
}


server.on('socket',(socket, port, address, protocol, proxy_ready)=>{

	// Implement your own proxy here! Do encryption, tunnelling, whatever! Go flippin' mental!
	// I plan to tunnel everything including SSH over an HTTP tunnel. For now, though, here is the plain proxy:
	var proxy = net.createConnection({port:port, host:address,localAddress:commander.localAddress||undefined}, proxy_ready);
	var localAddress,localPort;
	proxy.on('connect',()=>{
		info('%s:%d <== %s:%d ==> %s:%d',socket.remoteAddress,socket.remotePort,
			proxy.localAddress,proxy.localPort,proxy.remoteAddress,proxy.remotePort);
		localAddress=proxy.localAddress;
		localPort=proxy.localPort;
		proxy.pipe(socket);
		socket.pipe(proxy);
		proxy.on('error',e=>{
			console.error('connection error:',e.message);
			server.emit('connection_error',e.message);
		});
	}).on('error',e=>{
		console.error('proxy error:',e.message);
	});
	 
	socket.on('close', function(had_error) {
		try{
			if(localAddress && localPort)
				console.log('The proxy %s:%d closed', localAddress, localPort);
		else 
			console.error('Connect to %s:%d failed', address, port);
		}catch(err) {}
	});
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
}).on('socket_error',(socket,e)=>{
	console.error('socket error:',e);
}).on('socks_error',(socket,e)=>{
	console.error('socks error:',e);
}).listen(PORT, HOST);


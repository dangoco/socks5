
var net = require('net'),
	socks = require('./socks.js'),
	info = console.log.bind(console);

// Create server
// The server accepts SOCKS connections. This particular server acts as a proxy.
const users={};
if(process.argv[3]&&process.argv[4]){
	users[process.argv[3]]=process.argv[4];
}

var HOST='127.0.0.1',
	PORT='8888',
	server = socks.createServer();

server.on('socket',(socket, port, address, proxy_ready)=>{

	// Implement your own proxy here! Do encryption, tunnelling, whatever! Go flippin' mental!
	// I plan to tunnel everything including SSH over an HTTP tunnel. For now, though, here is the plain proxy:

	var proxy = net.createConnection({port:port, host:address,localAddress:process.argv[2]||undefined}, proxy_ready);
	var localAddress,localPort;
	proxy.on('connect',()=>{
		info('%s:%d <== %s:%d ==> %s:%d',socket.remoteAddress,socket.remotePort,
			proxy.localAddress,proxy.localPort,proxy.remoteAddress,proxy.remotePort);
		localAddress=proxy.localAddress;
		localPort=proxy.localPort;
		proxy.pipe(socket);
		socket.pipe(proxy);
		proxy.on('error',e=>{
			console.error('connection error:',e);
			server.emit('connection_error',e);
		});
		socket.on('error',e=>{
			console.error('proxy error:',e);
			server.emit('proxy_error',e);
		});
	});
	 
	proxy.on('close', function(had_error) {
		try {
			if(localAddress && localPort)
				console.log('The proxy %s:%d closed', localAddress, localPort);
		else 
			console.error('Connect to %s:%d failed', address, port);
			socket.end();
		} catch (err) {}
	});
}).on('error', function (e) {
	console.error('SERVER ERROR: %j', e);
	if (e.code == 'EADDRINUSE') {
		console.log('Address in use, retrying in 10 seconds...');
		setTimeout(function () {
			console.log('Reconnecting to %s:%s', HOST, PORT);
			server.close();
			server.listen(PORT, HOST);
		}, 10000);
	}
}).listen(PORT, HOST);

// vim: set filetype=javascript syntax=javascript :

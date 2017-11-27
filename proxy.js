
var net = require('net'),
	{createServer,Address,Port} = require('./socks.js'),
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

/*
udp request relay
parse source fragment and send them to the target
then receive the response and push back to source
*/
const dnsOpt={
	hints:dns.ADDRCONFIG | dns.V4MAPPED
}
function UDPHandle(socket, targetPort, targetAddress, CMD_REPLY){
	if(!net.isIP(targetAddress)){
		dns.lookup(targetAddress,dnsOpt,(err, address, family)=>{
			if(err){
				CMD_REPLY(0x04);//Host unreachable
				setTimeout(()=>socket.close(),2000);
				return;
			}
			UDPRelay(socket, targetPort, address, CMD_REPLY);
		});
		return;
	}
	UDPRelay(socket, targetPort, targetAddress, CMD_REPLY);
}
function UDPRelay(socket, targetPort, targetAddress, CMD_REPLY){
	let addrV;
	if(net.isIPv4(targetAddress))addrV=4;
	else if(net.isIPv6(targetAddress))addrV=6;
	else{
		CMD_REPLY(0x01);
		setTimeout(()=>socket.close(),2000);
		return;
	}
	info(`[UDP] ${socket.remoteAddress}:${socket.remotePort} ==> ${net.isIP(targetAddress)?targetAddress:targetAddress+'('+targetAddress+')'}:${targetPort}`);
	let relay=dgram.createSocket('udp'+addrV);
	relay.closed=false;
	relay.bind(()=>{
		CMD_REPLY();
	});
	//relay.send(msg, [offset, length,] port [, address] [, callback])
	relay.on('message',(msg,info)=>{
		if(info.port!==targetPort || info.address!== targetAddress){
			/*
				It MUST drop any datagrams
				arriving from any source IP address other than the one recorded for
				the particular association.
			*/
			return;
		}
		socket.write(Buffer.concat([socket.request,msg]));

	}).on('error',e=>{
		socket.destroy('relay error');
	}).on('close',()=>{
		if(relay.closed)return;
		relay.removeAllListeners();
	});

	socket.on('close',e=>{
		relay.close();
	}).on('data',chunk=>{
		if(chunk[1]!==0){//not support fragments
			return;//drop it
		}
		try{
			var addr=Address.read(chunk,3),
				port=Port.read(chunk,3);
		}catch(e){
			relay.close();
			return;
		}
		let dataStart=6;
		if (chunk[3] == ATYP.IP_V4) {
			dataStart+=4;
		} else if (chunk[3] == ATYP.DNS) {
			dataStart+=chunk[4];
		} else if (chunk[3] == ATYP.IP_V6) {
			dataStart+=16;
		}
		relay.send(chunk.subarray(dataStart),targetPort,targetAddress);
	});
}


server.on('socket',(socket, port, address, protocol, CMD_REPLY)=>{
	if(protocol==='tcp'){
		TCPRelay(socket, port, address, CMD_REPLY);
	}else if(protocol==='udp'){
		UDPHandle(socket, port, address, CMD_REPLY);
	}else{
		socket.destroy('not supported protocol');
	}
		
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


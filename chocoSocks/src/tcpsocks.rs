use std::{
	fs::{
		File,
		OpenOptions
	},
	io::{
		Read,
		Write,
	},
	mem::transmute,
	net::{
		IpAddr,
		Ipv4Addr,
		Shutdown,
		SocketAddr,
		TcpListener,
		TcpStream,
		UdpSocket,
	},
	sync::{
		Arc,
		Mutex,
	},
	thread,
	time::{
		self,
		SystemTime,
		UNIX_EPOCH,
	},
};

use std::os::windows::fs::OpenOptionsExt;

const FILE_SHARE_READ : u32 = 1;
const FILE_SHARE_WRITE : u32 = 2;
const FILE_SHARE_DELETE : u32 = 4;

use crate::{
	command::*,
	error::*,
	globalstate::*,
	pcap::*,
};

/* ================== SOCKS4 packet ================== */

#[repr(C)]
struct s4Packet
{
	socks_version: u8,
	command_type: u8,
	socks_port: u16,
	ip_address: Ipv4Addr,
}

impl s4Packet
{
	fn create_from_bytes(bytes: &[u8; 8]) -> s4Packet
	{
		let mut port: [u8; 2] = [0; 2];
		let mut ip_address: [u8; 4] = [0; 4];

		port.copy_from_slice(&bytes[2..4]);
		ip_address.copy_from_slice(&bytes[4..8]);

		// parse bytes
		s4Packet {
			socks_version: bytes[0],
			command_type: bytes[1],
			socks_port: unsafe { transmute::<[u8; 2], u16>(port) }.to_be(),
			ip_address: Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]),
		}
	}
}

pub fn handle_tcp_client(mut client_stream: TcpStream, mut global_state: globalState)
{
	let mut header: [u8; 8] = [0; 8];
	if let Err(_) = client_stream.read(&mut header)
	{
		return;
	}

	loop
	{
		let mut byte: [u8; 1] = [0; 1];
		if let Err(_) = client_stream.read(&mut byte)
		{
			return;
		}
		if byte[0] == 0
		{
			break;
		}
	}

	let mut packet_data: [u8; 16192] = [0; 16192];

	let littlePacket = s4Packet::create_from_bytes(&header);
	/*
	println!("Version: {:x?}", littlePacket.socks_version);
	println!("Command: {:x?}", littlePacket.command_type);
	println!("Port: {}", littlePacket.socks_port);
	println!("Address: {}", littlePacket.ip_address);
	*/

	let mut server_client_syn: u32 = 0;
	let mut client_server_syn: u32 = 0;

	let connection = SocketAddr::new(IpAddr::V4(littlePacket.ip_address), littlePacket.socks_port);
	println!(
		"Connecting to {} on port {}...",
		littlePacket.ip_address, littlePacket.socks_port
	);
	let mut server_stream = match TcpStream::connect(&connection)
	{
		Ok(v) =>
		{
			//println!("Connected to the server!");
			client_stream.write(&[0, 90, 0, 0, 0, 0, 0, 0]).unwrap();
			v
		}
		Err(_) =>
		{
			//println!("Couldn't connect to server...");
			client_stream.write(&[0, 91, 0, 0, 0, 0, 0, 0]).unwrap();
			return;
		}
	};

	client_stream
		.set_nonblocking(true)
		.expect("set_nonblocking call failed.");
	server_stream
		.set_nonblocking(true)
		.expect("set_nonblocking call failed.");

	let timestamp = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_millis();
	let filename = "stream".to_string() + &timestamp.to_string() + &".pcap".to_string();
	
	let mut file = match File::create(&filename)
	{
		Ok(v) => v,
		Err(_) =>
		{
			println!("Could not open file for writing.");
			return;
		}
	};

	let global_header = globalHeader::create_header();
	let header_data = unsafe { any_as_u8_slice(&global_header) };
	file.write(header_data);

	/* append to state */

	let state_id = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_millis()
		.to_string();

	let state_data = streamState::new(
		// dummy data
		littlePacket.ip_address.to_string(),
		littlePacket.socks_port.to_string(),
		"127.0.0.1".to_string(),
		"1337".to_string(),
		"random_pid".to_string(),
		"random_process_name".to_string(),
		filename,
		true,
		state_id.clone(),
	);

	if let Ok(mut unlocked_streams) = global_state.tcp_streams.lock()
	{
		unlocked_streams.insert(state_id.clone(), state_data);
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock tcpstreams");
	}

	let mut activity: bool = false;

	loop
	{
		activity = false;

		if let Ok(mut unlocked_command) = global_state.commands.lock()
		{
			match unlocked_command.get(&state_id) {
				Some(command_struct) => println!("{}", command_struct.command),
				None => continue
			}
		}
		
		let bytes_received = match server_stream.read(&mut packet_data)
		{
			Ok(v) => v,
			Err(_) => 0,
		};

		if bytes_received != 0
		{
			save_to_pcap(
				&packet_data[0..bytes_received].to_vec(),
				&1,
				&0,
				&server_client_syn,
				&client_server_syn,
				&mut file,
			);

			server_client_syn = server_client_syn.wrapping_add(bytes_received as u32);

			if let Err(_) = client_stream.write(&packet_data[0..bytes_received])
			{
				server_stream.shutdown(Shutdown::Both);

				if let Ok(mut unlocked_streams) = global_state.tcp_streams.lock()
				{
					unlocked_streams.remove(&state_id);
				}
				else
				{
					error_and_exit(file!(), line!(), "Failed to lock tcpstreams");
				}

				break;
			}
			activity = true;
		}

		let bytes_received = match client_stream.read(&mut packet_data)
		{
			Ok(v) => v,
			Err(_) => 0,
		};

		if bytes_received != 0
		{
			save_to_pcap(
				&packet_data[0..bytes_received].to_vec(),
				&0,
				&1,
				&client_server_syn,
				&server_client_syn,
				&mut file,
			);

			client_server_syn = client_server_syn.wrapping_add(bytes_received as u32);

			if let Err(_) = server_stream.write(&packet_data[0..bytes_received])
			{
				client_stream.shutdown(Shutdown::Both);

				if let Ok(mut unlocked_streams) = global_state.tcp_streams.lock()
				{
					unlocked_streams.remove(&state_id);
				}
				else
				{
					error_and_exit(file!(), line!(), "Failed to lock tcpstreams");
				}

				break;
			}
			activity = true;
		}

		if activity == false
		{
			thread::sleep(time::Duration::from_millis(10));
		}
	}
}

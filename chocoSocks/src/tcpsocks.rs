use std::{
	cell::RefCell,
	fs::{
		File,
		OpenOptions,
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

const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const FILE_SHARE_DELETE: u32 = 4;

use crate::{
	command::*,
	error::*,
	globalstate::*,
	pcap::*,
	python::*,
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

		s4Packet {
			socks_version: bytes[0],
			command_type: bytes[1],
			socks_port: unsafe { transmute::<[u8; 2], u16>(port) }.to_be(),
			ip_address: Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]),
		}
	}
}

thread_local! {
	pub static RECEIVER_SYN_T: RefCell<u32> = RefCell::new(0);  // Client syn
	pub static SENDER_SYN_T: RefCell<u32> = RefCell::new(0);    // Server syn
}

fn send_to_stream(
	global_state: &mut globalState,
	sending_stream: &mut TcpStream,
	receiving_stream: &mut TcpStream,
	server_to_client : bool,
	packet_bytes: &Vec<u8>,
	state_id: &String,
	file: &mut File,
) -> bool
{
	if server_to_client == true
	{
		let mut receiver_syn = RECEIVER_SYN_T.with(|syn| syn.borrow().clone());
		let mut sender_syn = SENDER_SYN_T.with(|syn| syn.borrow().clone());

		let mut src_ip : u32 = 0;
		let mut dst_ip : u32 = 0;

		if let IpAddr::V4(ipv4) = sending_stream.peer_addr().unwrap().ip() 
		{
			src_ip =  unsafe { transmute::<[u8; 4], u32>(ipv4.octets()) }.to_le();
		}

		if let IpAddr::V4(ipv4) = receiving_stream.peer_addr().unwrap().ip() 
		{
			dst_ip =  unsafe { transmute::<[u8; 4], u32>(ipv4.octets()) }.to_le();
		}

		save_to_pcap(&packet_bytes, &src_ip, &dst_ip, &sender_syn, &receiver_syn, file);

		sender_syn = sender_syn.wrapping_add(packet_bytes.len() as u32);

		SENDER_SYN_T.with(|syn| {
			*syn.borrow_mut() = sender_syn;
		});
	}
	else
	{
		let mut sender_syn = RECEIVER_SYN_T.with(|syn| syn.borrow().clone());
		let mut receiver_syn = SENDER_SYN_T.with(|syn| syn.borrow().clone());

		let mut src_ip : u32 = 0;
		let mut dst_ip : u32 = 0;

		if let IpAddr::V4(ipv4) = sending_stream.peer_addr().unwrap().ip() 
		{
			src_ip =  unsafe { transmute::<[u8; 4], u32>(ipv4.octets()) }.to_le();
		}

		if let IpAddr::V4(ipv4) = receiving_stream.peer_addr().unwrap().ip() 
		{
			dst_ip =  unsafe { transmute::<[u8; 4], u32>(ipv4.octets()) }.to_le();
		}

		save_to_pcap(&packet_bytes, &src_ip, &dst_ip, &sender_syn, &receiver_syn, file);

		sender_syn = sender_syn.wrapping_add(packet_bytes.len() as u32);

		RECEIVER_SYN_T.with(|syn| {
			*syn.borrow_mut() = sender_syn;
		});
	}

	if let Err(_) = receiving_stream.write(&packet_bytes)
	{
		return false;
	}
	return true;
}

fn echo_send_and_receive_packet(echo_tcpstream: &mut TcpStream, packet_bytes: Vec<u8>) -> Vec<u8>
{
	let mut received_bytes: [u8; 4] = [0; 4];

	echo_tcpstream
		.write(&(packet_bytes.len() as u32).to_ne_bytes())
		.unwrap();

	echo_tcpstream.write(&packet_bytes).unwrap();

	if let Err(_) = echo_tcpstream.read(&mut received_bytes)
	{
		error_and_exit(
			file!(),
			line!(),
			"Failed to receive intercepted packet length.",
		);
	}

	let mut intercept_amount = unsafe {
		std::mem::transmute::<[u8; 4], u32>([
			received_bytes[0],
			received_bytes[1],
			received_bytes[2],
			received_bytes[3],
		])
	}
	.to_le();

	let mut modified_bytes: Vec<u8> = vec![0; intercept_amount as usize];

	if let Err(_) = echo_tcpstream.read(&mut modified_bytes)
	{
		error_and_exit(file!(), line!(), "Failed to receive intercepted packet.");
	}

	modified_bytes
}

fn handle_packet_client_server(
	global_state: &mut globalState,
	src_ip: String,
	src_port: String,
	dest_ip: String,
	dest_port: String,
	packet_bytes: Vec<u8>,
) -> Vec<u8>
{
	let mut scripts: Vec<String> = Vec::new();

	if let Ok(global_python) = global_state.global_python_scripts.lock()
	{
		scripts = global_python.values().map(|ps| ps.script.clone()).collect();
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock python scripts");
	}

	if scripts.len() == 0
	{
		return packet_bytes;
	}

	match execute_python_handlers(
		scripts,
		&src_ip,
		&dest_ip,
		&"TCP".to_string(),
		&src_port,
		&dest_port,
		packet_bytes.clone(),
	)
	{
		Ok(v) => v,
		_ => packet_bytes,
	}
}

fn handle_packet_server_client(
	global_state: &mut globalState,
	src_ip: String,
	src_port: String,
	dest_ip: String,
	dest_port: String,
	packet_bytes: Vec<u8>,
) -> Vec<u8>
{
	let mut scripts: Vec<String> = Vec::new();

	if let Ok(global_python) = global_state.global_python_scripts.lock()
	{
		scripts = global_python.values().map(|ps| ps.script.clone()).collect();
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock python scripts");
	}

	if scripts.len() == 0
	{
		return packet_bytes;
	}

	match execute_python_handlers(
		scripts,
		&src_ip,
		&dest_ip,
		&"TCP".to_string(),
		&src_port,
		&dest_port,
		packet_bytes.clone(),
	)
	{
		Ok(v) => v,
		_ => packet_bytes,
	}
}

fn handle_relay_tick_nointercept(global_state: &mut globalState, client_stream : &mut TcpStream, server_stream : &mut TcpStream, state_id: &String, pcap_file : &mut File) -> std::result::Result<(),()>
{
	let mut packet_data: [u8; 16192] = [0; 16192];

	let mut bytes_received = match server_stream.read(&mut packet_data)
	{
		Ok(v) => v,
		_ => 0,
	};

	if (bytes_received != 0)
	{
		let mut server_to_client_bytes : Vec<u8> = packet_data[0..bytes_received].to_vec();

		let src_ip = server_stream.local_addr().unwrap().ip().to_string();
		let src_port = server_stream.local_addr().unwrap().port().to_string();

		let dst_ip = client_stream.local_addr().unwrap().ip().to_string();
		let dst_port = client_stream.local_addr().unwrap().port().to_string();		

		server_to_client_bytes = handle_packet_server_client(global_state,src_ip,src_port,dst_ip,dst_port,server_to_client_bytes.clone());

		if send_to_stream(global_state, server_stream, client_stream, true, &server_to_client_bytes, state_id, pcap_file) == false
		{
			return Err(());
		}
	}

	bytes_received = match client_stream.read(&mut packet_data)
	{
		Ok(v) => v,
		_ => 0,
	};

	if (bytes_received != 0)
	{
		let mut client_to_server_bytes : Vec<u8> = packet_data[0..bytes_received].to_vec();

		let src_ip = client_stream.local_addr().unwrap().ip().to_string();
		let src_port = client_stream.local_addr().unwrap().port().to_string();

		let dst_ip = server_stream.local_addr().unwrap().ip().to_string();
		let dst_port = server_stream.local_addr().unwrap().port().to_string();		

		client_to_server_bytes = handle_packet_client_server(global_state,src_ip,src_port,dst_ip,dst_port,client_to_server_bytes.clone());

		if send_to_stream(global_state, client_stream, server_stream, false, &client_to_server_bytes, state_id, pcap_file) == false
		{
			return Err(());
		}
	}

	Ok(())
}

fn handle_relay_tick_intercept(global_state: &mut globalState, client_stream : &mut TcpStream, server_stream : &mut TcpStream, echo_stream : &mut TcpStream, state_id: &String, pcap_file : &mut File) -> std::result::Result<(),()>
{
	let mut packet_data: [u8; 16192] = [0; 16192];

	let mut bytes_received = match server_stream.read(&mut packet_data)
	{
		Ok(v) => v,
		_ => 0,
	};

	if (bytes_received != 0)
	{
		let mut server_to_client_bytes : Vec<u8> = packet_data[0..bytes_received].to_vec();

		server_to_client_bytes = echo_send_and_receive_packet(echo_stream, server_to_client_bytes);

		if send_to_stream(global_state, server_stream, client_stream, true, &server_to_client_bytes, state_id, pcap_file) == false
		{
			return Err(());
		}
	}

	bytes_received = match client_stream.read(&mut packet_data)
	{
		Ok(v) => v,
		_ => 0,
	};

	if (bytes_received != 0)
	{
		let mut client_to_server_bytes : Vec<u8> = packet_data[0..bytes_received].to_vec();

		client_to_server_bytes = echo_send_and_receive_packet(echo_stream, client_to_server_bytes);

		if send_to_stream(global_state, client_stream, server_stream, false, &client_to_server_bytes, state_id, pcap_file) == false
		{
			return Err(());
		}
	}

	Ok(())
}

pub fn handle_command_repeat(global_state: &mut globalState, client_stream : &mut TcpStream, server_stream : &mut TcpStream, repeater_bytes : &Vec<u8>, state_id: &String, pcap_file : &mut File) -> std::result::Result<(),()>
{
	match send_to_stream(global_state, client_stream, server_stream, false, repeater_bytes, state_id, pcap_file)
	{
		true => Ok(()),
		false => Err(()),
	}
}

pub fn handle_tcp_client(mut client_stream: TcpStream, mut global_state: globalState)
{	
	debug_print(file!(), line!(), "Receiving SOCKS request");

	let mut header: [u8; 8] = [0; 8];
	if let Err(_) = client_stream.read(&mut header)
	{
		return;
	}

	debug_print(file!(), line!(), "Received SOCKS request");

	loop
	{
		let mut byte: [u8; 1] = [0; 1];
		if let Err(_) = client_stream.read(&mut byte)
		{
			debug_print(file!(), line!(), "Error reading last SOCKS byte");
			return;
		}
		if byte[0] == 0
		{
			break;
		}
	}

	debug_print(file!(), line!(), "SOCKS request finished");

	let mut packet_data: [u8; 16192] = [0; 16192];

	let littlePacket = s4Packet::create_from_bytes(&header);

	let connection = SocketAddr::new(IpAddr::V4(littlePacket.ip_address), littlePacket.socks_port);

	println!(
		"Connecting to {} on port {}...",
		littlePacket.ip_address, littlePacket.socks_port
	);

	let mut server_stream = match TcpStream::connect(&connection)
	{
		Ok(v) =>
		{
			client_stream.write(&[0, 90, 0, 0, 0, 0, 0, 0]).unwrap();
			v
		}
		Err(_) =>
		{
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

	let dest_ip = littlePacket.ip_address.to_string();
	let dest_port = littlePacket.socks_port.to_string();

	let src_ip = client_stream.local_addr().unwrap().ip().to_string();
	let src_port = client_stream.local_addr().unwrap().port().to_string();

	let state_data = streamState::new(
		dest_ip.clone(),
		dest_port.clone(),
		src_ip.clone(),
		src_port.clone(),
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
	let mut intercept: bool = false;
	let mut repeater: bool = false;
	let mut global_intercept: bool = false;
	let mut echo_tcpstream: Option<TcpStream> = None;

	loop
	{
		activity = false;

		if let Ok(mut unlocked_global) = global_state.global_intercept.lock()
		{
			global_intercept = *unlocked_global;
		}
		else
		{
			error_and_exit(file!(), line!(), "Failed to lock global intercept.");
		}

		let mut current_command: Option<commandState> = None;

		if let Ok(mut unlocked_command) = global_state.commands.lock()
		{
			current_command = match unlocked_command.get_mut(&state_id)
			{
				Some(v) => v.pop_front(),
				None => None,
			};
		}

		if let Some(real_command) = current_command
		{
			activity = true;

			match real_command.command.as_ref()
			{
				"repeat_packet" =>
				{
					let packet_bytes = real_command.parameters[0].clone();

					handle_command_repeat(&mut global_state, &mut client_stream, &mut server_stream, &packet_bytes, &state_id, &mut file);

					continue;
				},
				"toggle_intercept" =>
				{
					let toggle_flag: String = String::from_utf8(real_command.parameters[0].clone()).expect("Invalid UTF8 in toggle flag.");

					match toggle_flag.as_ref()
					{
						"true" =>
						{
							let connection_string: String = String::from_utf8(real_command.parameters[1].clone()).expect("Invalid UTF8 in connection string.");
							intercept = true;

							echo_tcpstream = match TcpStream::connect(&connection_string)
							{
								Ok(v) => Some(v),
								_ => None,
							};
						}
						"false" => intercept = false,
						_ =>
						{
							error_and_continue(
								file!(),
								line!(),
								"Invalid toggle value: must be true or false",
							);
						}
					}
				},
				_ =>
				{
					error_and_continue(
						file!(),
						line!(),
						"Invalid command: invalid number of parameters",
					);
				}
			}
		}

		if (global_intercept == true)
		{
			// This means an error occured while establishing the error stream
			if intercept == true && echo_tcpstream.is_none() == true
			{
				error_and_continue(
					file!(),
					line!(),
					"Invalid command: invalid stream state: intercept == true and echo_steam == None",
				);

				break;
			}

			// This means a global intercept is set, but this stream is not yet connected to the UI
			if (intercept == false)
			{
				thread::sleep_ms(10);
				continue;
			}

			let mut my_echo_stream = echo_tcpstream.take().unwrap();

			if let Err(_) = handle_relay_tick_intercept(&mut global_state, &mut client_stream, &mut server_stream, &mut my_echo_stream, &state_id, &mut file)
			{
				break;
			}

			echo_tcpstream = Some(my_echo_stream);

			activity = true;
		}
		else if intercept == true
		{
			if echo_tcpstream.is_none() == true
			{
				error_and_continue(
					file!(),
					line!(),
					"Invalid command: invalid stream state: intercept == true and echo_steam == None",
				);

				break;
			}

			let mut my_echo_stream = echo_tcpstream.take().unwrap();

			if let Err(_) = handle_relay_tick_intercept(&mut global_state, &mut client_stream, &mut server_stream, &mut my_echo_stream, &state_id, &mut file)
			{
				break;
			}

			echo_tcpstream = Some(my_echo_stream);

			activity = true;
		}
		else
		{
			if let Err(_) = handle_relay_tick_nointercept(&mut global_state,&mut client_stream, &mut server_stream, &state_id, &mut file)
			{
				break;
			}

			activity = true;
		}

		if activity == true
		{
			thread::sleep_ms(10);
		}
	}

	client_stream.shutdown(Shutdown::Both);
	server_stream.shutdown(Shutdown::Both);

	if let Some(intercept_stream) = echo_tcpstream
	{
		intercept_stream.shutdown(Shutdown::Both);
	}

	if let Ok(mut unlocked_streams) = global_state.tcp_streams.lock()
	{
		unlocked_streams.remove(&state_id);
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock tcpstreams");
	}
}

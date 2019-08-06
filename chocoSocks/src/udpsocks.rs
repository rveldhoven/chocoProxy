use std::{
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

const REQUEST_MODE_WRITE: u8 = 1;
const REQUEST_MODE_READ: u8 = 2;

use crate::{
	command::*,
	error::*,
	globalstate::*,
	pcap::*,
	python::*,
};

#[repr(C)]
struct UDPRequest
{
	request_mode: u8,
	ip: u32,
	port: u16,
}

impl UDPRequest
{
	fn create_from_bytes(bytes: &[u8]) -> UDPRequest
	{
		let mut ip: [u8; 4] = [0; 4];
		let mut port: [u8; 2] = [0; 2];

		ip.copy_from_slice(&bytes[1..5]);
		port.copy_from_slice(&bytes[5..7]);

		// parse bytes
		UDPRequest {
			request_mode: bytes[0],
			ip: unsafe { transmute::<[u8; 4], u32>(ip) }.to_be(),
			port: unsafe { transmute::<[u8; 2], u16>(port) }.to_be(),
		}
	}
}

fn receive_packet_from_client(client_stream: &mut TcpStream) -> std::result::Result<Vec<u8>, ()>
{
	let mut bytes_receive_size: [u8; 4] = [0; 4];
	if let Err(_) = client_stream.read(&mut bytes_receive_size)
	{
		error_and_continue(
			file!(),
			line!(),
			"Failed to receive intercepted packet length.",
		);
		return Err(());
	}

	let mut intercept_amount = unsafe {
		std::mem::transmute::<[u8; 4], u32>([
			bytes_receive_size[0],
			bytes_receive_size[1],
			bytes_receive_size[2],
			bytes_receive_size[3],
		])
	}
	.to_le();

	//println!("UDP socks: receiving: {} bytes", intercept_amount);

	let mut result_bytes: Vec<u8> = vec![0; intercept_amount as usize];

	if let Err(_) = client_stream.read(&mut result_bytes)
	{
		error_and_continue(file!(), line!(), "Failed to receive intercepted packet.");
		return Err(());
	}

	Ok(result_bytes)
}

fn send_packet_to_client(
	client_stream: &mut TcpStream,
	packet_bytes: &Vec<u8>,
) -> std::result::Result<(), ()>
{
	if let Err(_) = client_stream.write(&(packet_bytes.len() as u32).to_ne_bytes())
	{
		return Err(());
	}

	if let Err(_) = client_stream.write(&packet_bytes[..])
	{
		return Err(());
	}

	Ok(())
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

fn handle_udp_packet(
	mut global_state: globalState,
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
		&"UDP".to_string(),
		&src_port,
		&dest_port,
		packet_bytes.clone(),
	)
	{
		Ok(v) => v,
		_ => packet_bytes,
	}
}

fn handle_relay_tick_intercept(global_state: &mut globalState, client_stream : &mut TcpStream, echo_stream : &mut TcpStream, state_id: &String, pcap_file : &mut File) -> std::result::Result<(),()>
{
	let mut packet_data: [u8; 16192] = [0; 16192];

	let mut bytes_received = match client_stream.read(&mut packet_data)
	{
		Ok(v) => v,
		_ => 0,
	};

	if (bytes_received == 0)
	{
		return Ok(());
	}

	let mut packet_bytes : Vec<u8> = packet_data[0..bytes_received].to_vec();

	let mut request_struct = UDPRequest::create_from_bytes(&packet_bytes[0..7]);

	let dest_ip = Ipv4Addr::new(
		packet_bytes[1],
		packet_bytes[2],
		packet_bytes[3],
		packet_bytes[4],
	);

	packet_bytes = packet_bytes[7..].to_vec();

	let str_dest_ip = dest_ip.to_string();
	let str_dest_port = request_struct.port.to_string();

	let src_ip = client_stream.local_addr().unwrap().ip().to_string();
	let src_port = client_stream.local_addr().unwrap().port().to_string();

	packet_bytes = echo_send_and_receive_packet(echo_stream, packet_bytes);

	if request_struct.request_mode == REQUEST_MODE_WRITE
	{
		save_udp_to_pcap(&packet_bytes, &0xffffffff, &request_struct.ip, pcap_file);
	}
	else
	{
		save_udp_to_pcap(&packet_bytes, &request_struct.ip, &0xffffffff, pcap_file);
	}

	if let Err(_) = send_packet_to_client(client_stream, &packet_bytes)
	{
		return Err(());
	}

	Ok(())
}

fn handle_relay_tick_nointercept(global_state: &mut globalState, client_stream : &mut TcpStream, state_id: &String, pcap_file : &mut File) -> std::result::Result<(),()>
{	
	let mut packet_data: [u8; 16192] = [0; 16192];

	let mut bytes_received = match client_stream.read(&mut packet_data)
	{
		Ok(v) => v,
		_ => 0,
	};

	if (bytes_received == 0)
	{
		return Ok(());
	}

	let mut packet_bytes : Vec<u8> = packet_data[0..bytes_received].to_vec();

	let mut request_struct = UDPRequest::create_from_bytes(&packet_bytes[0..7]);

	let dest_ip = Ipv4Addr::new(
		packet_bytes[1],
		packet_bytes[2],
		packet_bytes[3],
		packet_bytes[4],
	);

	packet_bytes = packet_bytes[7..].to_vec();

	let str_dest_ip = dest_ip.to_string();
	let str_dest_port = request_struct.port.to_string();

	let src_ip = client_stream.local_addr().unwrap().ip().to_string();
	let src_port = client_stream.local_addr().unwrap().port().to_string();

	packet_bytes = handle_udp_packet(
		global_state.clone(),
		src_ip.clone(),
		src_port.clone(),
		str_dest_ip.clone(),
		str_dest_port.clone(),
		packet_bytes,
	);

	if request_struct.request_mode == REQUEST_MODE_WRITE
	{
		save_udp_to_pcap(&packet_bytes, &0xffffffff, &request_struct.ip, pcap_file);
	}
	else
	{
		save_udp_to_pcap(&packet_bytes, &request_struct.ip, &0xffffffff, pcap_file);
	}

	if let Err(_) = send_packet_to_client(client_stream, &packet_bytes)
	{
		return Err(());
	}

	Ok(())
}

pub fn handle_udp_client(mut client_stream: TcpStream, mut global_state: globalState)
{
	let mut packet_bytes : Vec<u8> = Vec::new();
	let mut request_struct = UDPRequest {
		request_mode: 0,
		ip: 0,
		port: 0,
	};

	let mut activity: bool = false;
	let mut intercept: bool = false;
	let mut repeater: bool = false;
	let mut global_intercept: bool = false;
	let mut echo_tcpstream: Option<TcpStream> = None;

	let timestamp = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_millis();

	let filename = "udpstream".to_string() + &timestamp.to_string() + &".pcap".to_string();

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

	client_stream
		.set_nonblocking(true)
		.expect("set_nonblocking call failed.");

	/* append to state */

	let state_id = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_millis()
		.to_string();

	let state_data = udpStreamState::new(
		"not applicable".to_string(),
		"not applicable".to_string(),
		"not applicable".to_string(),
		"not applicable".to_string(),
		"random_pid".to_string(),
		"random_process_name".to_string(),
		filename,
		true,
		state_id.clone(),
	);

	if let Ok(mut unlocked_streams) = global_state.udp_streams.lock()
	{
		unlocked_streams.insert(state_id.clone(), state_data);
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock udpstreams");
	}

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

			if let Err(_) = handle_relay_tick_intercept(&mut global_state, &mut client_stream, &mut my_echo_stream, &state_id, &mut file)
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

			if let Err(_) = handle_relay_tick_intercept(&mut global_state, &mut client_stream, &mut my_echo_stream, &state_id, &mut file)
			{
				break;
			}
			
			echo_tcpstream = Some(my_echo_stream);

			activity = true;
		}
		else
		{
			if let Err(_) = handle_relay_tick_nointercept(&mut global_state, &mut client_stream, &state_id, &mut file)
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

	if let Ok(mut unlocked_streams) = global_state.udp_streams.lock()
	{
		unlocked_streams.remove(&state_id);
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock udpstreams");
	}
}

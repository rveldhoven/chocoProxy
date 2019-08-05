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
		let mut ip: [u8;4] = [0;4];
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

fn receive_packet_from_client(client_stream : &mut TcpStream) -> std::result::Result<Vec<u8>, ()>
{
	let mut bytes_receive_size : [u8; 4] = [0; 4];
	if let Err(_) = client_stream.read(&mut bytes_receive_size)
	{
		error_and_continue(file!(), line!(), "Failed to receive intercepted packet length.");
		return Err(());
	}
	
	let mut intercept_amount = unsafe { 
		std::mem::transmute::<[u8; 4], u32>(
		[bytes_receive_size[0], bytes_receive_size[1], bytes_receive_size[2], bytes_receive_size[3]]
		)}.to_le();
		
	//println!("UDP socks: receiving: {} bytes", intercept_amount);
		
	let mut result_bytes : Vec<u8> = vec![0; intercept_amount as usize];
	
	if let Err(_) = client_stream.read(&mut result_bytes)
	{
		error_and_continue(file!(), line!(), "Failed to receive intercepted packet.");
		return Err(());
	}
	
	Ok(result_bytes)
}

fn send_packet_to_client(client_stream : &mut TcpStream, packet_bytes : &Vec<u8>) -> std::result::Result<(), ()>
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

pub fn handle_udp_client(mut client_stream: TcpStream, mut global_state: globalState)
{
	let mut packet_bytes = Vec::new();
	let mut request_struct = UDPRequest
	{ 
		request_mode: 0,
		ip: 0,
		port: 0,
	};
	
	let mut activity: bool = false;
	let mut intercept: bool = false;
	let mut repeater: bool = false;
	let mut global_intercept: bool = false;
	let mut echo_tcpstream : Option<TcpStream> = None;

	packet_bytes = match receive_packet_from_client(&mut client_stream)
	{
		Ok(v) => v,
		_ => return,
	};
	
	request_struct = UDPRequest::create_from_bytes(&packet_bytes[0..7]);

	let dest_ip = Ipv4Addr::new(packet_bytes[1], packet_bytes[2], packet_bytes[3], packet_bytes[4]);
	packet_bytes = packet_bytes[7..].to_vec();
	
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

	/* append to state */

	let state_id = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_millis()
		.to_string();

	let str_dest_ip = dest_ip.to_string();
	let str_dest_port = request_struct.port.to_string();

	let src_ip = client_stream.local_addr().unwrap().ip().to_string();
	let src_port = client_stream.local_addr().unwrap().port().to_string();

	let state_data = udpStreamState::new(
		str_dest_ip.clone(),
		str_dest_port.clone(),
		src_ip.clone(),
		src_port.clone(),
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
		if intercept == false
		{
			packet_bytes = handle_udp_packet(
				global_state.clone(),
				src_ip.clone(),
				src_port.clone(),
				str_dest_ip.clone(),
				str_dest_port.clone(),
				packet_bytes,
			);
		}
	
		if let Err(_) = send_packet_to_client(&mut client_stream, &packet_bytes)
		{
			break;
		}
	
		if request_struct.request_mode == REQUEST_MODE_WRITE
		{
			save_udp_to_pcap(&packet_bytes, &0, &request_struct.ip, &mut file);
		}
		else
		{
			save_udp_to_pcap(&packet_bytes, &request_struct.ip, &0, &mut file);
		}
		
		
		packet_bytes = match receive_packet_from_client(&mut client_stream)
		{
			Ok(v) => v,
			_ => break,
		};
		
		request_struct = UDPRequest::create_from_bytes(&packet_bytes[0..7]);
		packet_bytes = packet_bytes[7..].to_vec();
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




















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
	cell::RefCell,
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

		// parse bytes
		s4Packet {
			socks_version: bytes[0],
			command_type: bytes[1],
			socks_port: unsafe { transmute::<[u8; 2], u16>(port) }.to_be(),
			ip_address: Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]),
		}
	}
}

fn process_command(
	mut global_state: globalState, 
	state_id: &String, 
	repeater: &mut bool, 
	intercept: &mut bool, 
	client_to_server_bytes: &mut Vec<u8>
) -> Option<String>
{
	let mut current_command : Option<commandState> = None;
	
	if let Ok(mut unlocked_command) = global_state.commands.lock()
	{
		current_command = match unlocked_command.get_mut(state_id)
			{
				Some(v) => v.pop_front(),
				None => None,
			};
	}
	
	let real_command = match current_command 
	{
		Some(v) => v,
		_ => return None,
	};
	
	match real_command.command.as_ref()
	{
		"repeat_packet" => 
		{
			*client_to_server_bytes = real_command.parameters[0].clone();
			*repeater = true;
			None
		},		
		"toggle_intercept" => 
		{
			let toggle_flag: String =
				String::from_utf8(real_command.parameters[0].clone()).expect("Invalid UTF8 in toggle flag.");
			match toggle_flag.as_ref()
			{
				"true" => 
				{
					*intercept = true;
					let connection_string: String =
						String::from_utf8(real_command.parameters[1].clone()).expect("Invalid UTF8 in connection string.");
					Some(connection_string)
				},
				"false" => None,
				_ => 
				{
					error_and_continue(file!(),line!(),"Invalid toggle value: must be true or false");
					None
				},
			}
		}
		_ => 
		{
			error_and_continue(file!(),line!(),"Invalid command: invalid number of parameters");
			None
		},
	}
}

thread_local!{
	pub static mut receiver_syn_t: RefCell<u32> = RefCell::new(0); // server_client_syn
	pub static mut sender_syn_t: RefCell<u32> = RefCell::new(0); // client_server_syn
	}

fn send_to_stream(
	mut global_state: globalState, 
	sending_stream: &mut TcpStream, 
	receiving_stream: &mut TcpStream, 
	packet_bytes : Vec<u8>,
	state_id: &String,
	file: &mut File
	) -> bool
{
	let receiver_syn = receiver_syn_t.with(|syn| {
        *syn.borrow().clone();
    });
	let sender_syn = sender_syn_t.with(|syn| {
        *syn.borrow().clone();
    });

	save_to_pcap(
		&packet_bytes,
		&0,
		&1,
		&sender_syn,
		&receiver_syn,
		&mut file
	);
	
	sender_syn_t.with(|syn| {
        *syn.borrow_mut() = *syn.borrow_mut().wrapping_add(packet_bytes.len() as u32);
    });

	if let Err(_) = receiving_stream.write(&packet_bytes)
	{
		sending_stream.shutdown(Shutdown::Both);

		if let Ok(mut unlocked_streams) = global_state.tcp_streams.lock()
		{
			unlocked_streams.remove(state_id);
		}
		else
		{
			error_and_exit(file!(), line!(), "Failed to lock tcpstreams");
		}
		false
	}
	true
}

fn echo_send_and_receive_packet(echo_tcpstream: &mut TcpStream, packet_bytes : Vec<u8>) -> Vec<u8>
{
	let mut received_bytes : [u8; 4] = [0; 4];
	echo_tcpstream
		.write(&(packet_bytes.len() as u32).to_ne_bytes())
		.unwrap();
	echo_tcpstream.write(&packet_bytes).unwrap();
	if let Err(_) = echo_tcpstream.read(&mut received_bytes)
	{
		error_and_exit(file!(), line!(), "Failed to receive intercepted packet length.");
	}
	let mut intercept_amount = unsafe { 
		std::mem::transmute::<[u8; 4], u32>(
		[received_bytes[0], received_bytes[1], received_bytes[2], received_bytes[3]]
		)}.to_le();
	let mut modified_bytes : Vec<u8> = Vec::with_capacity(intercept_amount as usize);
	if let Err(_) = echo_tcpstream.read(&mut modified_bytes)
	{
		error_and_exit(file!(), line!(), "Failed to receive intercepted packet.");
	}
	modified_bytes
}

fn handle_packet_client_server(
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

fn handle_packet_server_client(
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
	let mut echo_tcpstream : Option<TcpStream> = None;
	
	loop
	{
		activity = false;
		intercept = false;
		repeater = false;
		global_intercept = false;
		
		/* ================== Check for intercept ================== */
		
		if let Ok(mut unlocked_global) = global_state.global_intercept.lock()
		{
			global_intercept = *unlocked_global;
		}
		else
		{
			error_and_exit(file!(), line!(), "Failed to lock global intercept.");
		}
		
		let mut client_to_server_bytes : Vec<u8> = Vec::new();
		if let Some(connection_string) = process_command(global_state.clone(), &state_id, &mut repeater, &mut intercept, &mut client_to_server_bytes)
		{
			echo_tcpstream = match TcpStream::connect(connection_string)
			{
				Ok(v) => Some(v),
				Err(_) => None,
			};
		}
		
		if repeater == true 
		{
/*			save_to_pcap(
				&client_to_server_bytes,
				&0,
				&1,
				&client_server_syn,
				&server_client_syn,
				&mut file,
			);
			
			client_server_syn = client_server_syn.wrapping_add(client_to_server_bytes.len() as u32);

			if let Err(_) = server_stream.write(&client_to_server_bytes)
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
			}*/
			activity = true;
		} 
		
		/* ================== Receive from server ================== */
		
		let bytes_received = match server_stream.read(&mut packet_data)
		{
			Ok(v) => v,
			Err(_) => 0,
		};

		if bytes_received != 0
		{
			let mut server_to_client_bytes = packet_data[0..bytes_received].to_vec();

			server_to_client_bytes = handle_packet_server_client(
				global_state.clone(),
				src_ip.clone(),
				src_port.clone(),
				dest_ip.clone(),
				dest_port.clone(),
				server_to_client_bytes,
			);

/*			save_to_pcap(
				&server_to_client_bytes,
				&1,
				&0,
				&server_client_syn,
				&client_server_syn,
				&mut file,
			);

			server_client_syn = server_client_syn.wrapping_add(server_to_client_bytes.len() as u32);

			if let Err(_) = client_stream.write(&server_to_client_bytes)
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
			}*/
			activity = true;
		}
		
		/* ================== Client send to server ================== */

		let bytes_received = match client_stream.read(&mut packet_data)
		{
			Ok(v) => v,
			Err(_) => 0,
		};

		if bytes_received != 0
		{
			while global_intercept == true
			{
				if intercept == true
				{
					let mut temp_tcpstream = match echo_tcpstream
					{
						Some(v) => v,
						None => 
						{
							error_and_exit(file!(), line!(), "No echo stream found.");
							panic!("No echo stream found.");
						},
					};
					
				client_to_server_bytes = echo_send_and_receive_packet(&mut temp_tcpstream, client_to_server_bytes);
				echo_tcpstream = Some(temp_tcpstream);
				
				}
				
				if let Ok(mut unlocked_global) = global_state.global_intercept.lock()
				{
					match *unlocked_global
					{
						true =>
						{
							thread::sleep(time::Duration::from_millis(10));
							continue;
						},
						false => break,
					}
				}
				else
				{
					error_and_exit(file!(), line!(), "Failed to lock global intercept.");
				}
			}
			
			let mut client_to_server_bytes = packet_data[0..bytes_received].to_vec();
			
			if intercept == true
			{
				let mut temp_tcpstream = match echo_tcpstream
				{
					Some(v) => v,
					None => 
					{
						error_and_exit(file!(), line!(), "No echo stream found.");
						panic!("No echo stream found.");
					},
				};
				client_to_server_bytes = echo_send_and_receive_packet(&mut temp_tcpstream, client_to_server_bytes);
				echo_tcpstream = Some(temp_tcpstream);
			}
			else
			{
				client_to_server_bytes = handle_packet_client_server(
				global_state.clone(),
				src_ip.clone(),
				src_port.clone(),
				dest_ip.clone(),
				dest_port.clone(),
				client_to_server_bytes,
				);
			}

/*			save_to_pcap(
				&client_to_server_bytes,
				&0,
				&1,
				&client_server_syn,
				&server_client_syn,
				&mut file,
			);

			client_server_syn = client_server_syn.wrapping_add(client_to_server_bytes.len() as u32);

			if let Err(_) = server_stream.write(&client_to_server_bytes)
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
			} */
			activity = true;
		}
		
		if activity == false
		{
			thread::sleep(time::Duration::from_millis(10));
		}
	}
}

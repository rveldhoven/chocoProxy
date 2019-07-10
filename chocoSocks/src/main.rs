pub mod pcap;
pub mod error;

use std::net::{TcpListener, TcpStream, UdpSocket, SocketAddr, Ipv4Addr, IpAddr, Shutdown};
use std::{thread,time};
use std::time::{UNIX_EPOCH, SystemTime};
use std::io::{Read, Write};
use std::mem::transmute;
use std::fs::File;

use crate::pcap::*;
use crate::error::*;

#[repr(C)]
struct s4Packet
{
	socks_version : u8,
	command_type : u8,
	socks_port : u16,
	ip_address : Ipv4Addr
}

impl s4Packet
{
	fn create_from_bytes(bytes : &[u8;8]) -> s4Packet
	{
		let mut port : [u8;2] = [0;2];
		let mut ip_address : [u8;4] = [0;4];
		
		port.copy_from_slice(&bytes[2..4]);
		ip_address.copy_from_slice(&bytes[4..8]);
	
		// parse bytes
		s4Packet{ 
			socks_version : bytes[0], 
			command_type : bytes[1],
			socks_port : unsafe { transmute::<[u8;2], u16>(port) }.to_be(),
			ip_address : Ipv4Addr::new(bytes[4],bytes[5],bytes[6],bytes[7])
			}
	}
}

fn handle_client(mut client_stream : TcpStream) 
{
	let mut header:[u8; 8] = [0; 8];
	if let Err(_) = client_stream.read(&mut header)
	{
		return;
	}
	
	loop 
	{
		let mut byte : [u8;1] = [0; 1];
		if let Err(_) = client_stream.read(&mut byte)
		{
			return;
		}
		if byte[0] == 0
		{
			break;
		}
	}

	let mut packet_data : [u8; 16192] = [0; 16192];
	
	let littlePacket = s4Packet::create_from_bytes(&header);
	/*
	println!("Version: {:x?}", littlePacket.socks_version);
	println!("Command: {:x?}", littlePacket.command_type);
	println!("Port: {}", littlePacket.socks_port);
	println!("Address: {}", littlePacket.ip_address);
	*/
	
	let connection = SocketAddr::new(IpAddr::V4(littlePacket.ip_address),littlePacket.socks_port);
	println!("Connecting to {} on port {}...", littlePacket.ip_address, littlePacket.socks_port);
	let mut server_stream = match TcpStream::connect(&connection)
	{
		Ok(v) => 
		{
			//println!("Connected to the server!");
			client_stream.write(&[ 0, 90, 0, 0, 0, 0, 0, 0 ]).unwrap();
			v
		},
		Err(_) => 
		{
			//println!("Couldn't connect to server...");
			client_stream.write(&[ 0, 91, 0, 0, 0, 0, 0, 0 ]).unwrap();
			return;
		},
	};
	
	client_stream.set_nonblocking(true).expect("set_nonblocking call failed.");
	server_stream.set_nonblocking(true).expect("set_nonblocking call failed.");
	
	let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
	let mut file = match File::create("stream".to_string() + &timestamp.to_string() + &".pcap".to_string())
	{
		Ok(v) => v,
		Err(_) => 
		{
			println!("Could not open file for writing.");
			return;
		},
	};
	let global_header = pcap::globalHeader::create_header();
	let header_data = unsafe { any_as_u8_slice(&global_header) };
	file.write(header_data);
	
	let mut activity : bool = false;
	
	loop 
	{
		activity = false;
		let bytes_received = match server_stream.read(&mut packet_data)
		{
			Ok(v) => v,
			Err(_) => 0,
		};
		if bytes_received != 0
		{
			pcap::save_to_pcap(&pcapPacket::create_from_bytes(&packet_data[0..bytes_received]), 1, &mut file);
			if let Err(_) = client_stream.write(&packet_data[0..bytes_received])
			{
				server_stream.shutdown(Shutdown::Both);
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
			pcap::save_to_pcap(&pcapPacket::create_from_bytes(&packet_data[0..bytes_received]), 1, &mut file);
			if let Err(_) = server_stream.write(&packet_data[0..bytes_received])
			{
				client_stream.shutdown(Shutdown::Both);
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

fn main() 
{

/* ================== Command listener ================== */

	let mut command : [u8; 1024] = [0; 1024];
	let command_listener = match UdpSocket::bind("127.0.0.1:1001")
	{
		Ok(v) => v,
		Err(_) => panic!("Failed to open command UDP listener."),
	};
	
	loop 
	{
		let (number_of_bytes, src_addr) = command_listener.recv_from(&mut command).expect("Didn't receive command data.");
		
		match &command[0..2] 
		{
			&[0x30,0x0a] => println!("first command"),
			&[0x31,0x0a] => println!("second command"),
			&[0x32,0x0a] => println!("third command"),
			_ => println!("Unknown command"),
		}
	}
	
/* ================== TCP listener ================== */

	let tcp_listener = match TcpListener::bind("127.0.0.1:80") 
	{
		Ok(v) => v,
		Err(_) => panic!("Failed to open TCP listener."),
	};
	
	for stream in tcp_listener.incoming() 
	{
		let thread = thread::spawn(move || 
			{
				handle_client(stream.expect("Connection failed"));
			});
	}

/* ================== UDP listener ================== */
	
	let udp_listener = match UdpSocket::bind("127.0.0.1:81")
	{
		Ok(v) => v,
		Err(_) => panic!("Failed to open UDP listener."),
	};
}

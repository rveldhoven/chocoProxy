pub mod pcap;

use std::net::{TcpListener, TcpStream, SocketAddr, Ipv4Addr, IpAddr, Shutdown};
use std::{thread,time};
use std::time::{UNIX_EPOCH, SystemTime};
use std::io::{Read, Write};
use std::mem::transmute;
use crate::pcap::*;
use std::fs::File;

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
	let mut file = File::create("pcaps\\stream".to_string() + &timestamp.to_string());
	
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
	let listener = match TcpListener::bind("127.0.0.1:80") 
	{
		Ok(v) => v,
		Err(_) => panic!("Failed to open listener."),
	};
		
	for stream in listener.incoming() 
	{
		let thread = thread::spawn(move || 
			{
				handle_client(stream.expect("Connection failed"));
			});
	}
	
		
}

use std::net::{TcpListener, TcpStream, UdpSocket, SocketAddr, Ipv4Addr, IpAddr, Shutdown};
use std::{thread};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::str::from_utf8;

use crate::pcap::*;
use crate::error::*;
use crate::globalstate::*;

fn handle_command_client(mut command_stream : TcpStream, mut global_state : globalState)
{
	let mut packet_data : [u8; 16192] = [0; 16192];

	loop 
	{
		let bytes_received = match command_stream.read(&mut packet_data)
		{
			Ok(v) => v,
			Err(_) => 
			{
				error_and_exit(file!(), line!(), "Failed to receive command");
				0
			},
		};

		if bytes_received == 0
		{
			continue;
		}
		
		let string_command = match from_utf8(&packet_data[0..bytes_received])
		{
			Ok(v) => v,
			_ => 
			{	
				error_and_exit(file!(), line!(), "Failed to parse command");
				&""
			},
		};
	}
}

pub fn command_client_handler(mut global_state : globalState)
{
	let command_listener = match TcpListener::bind("127.0.0.1:81")
	{
		Ok(v) => v,
		Err(_) => panic!("Failed to open command TCP listener."),
	};
	
	for stream in command_listener.incoming() 
	{
		let thread_global_state = global_state.clone();
		let thread = thread::spawn(move || 
		{
			handle_command_client(stream.expect("Connection failed"), thread_global_state);
		});
	}
}

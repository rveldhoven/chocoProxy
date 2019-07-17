use std::{
	io::{
		Read,
		Write,
	},
	net::{
		IpAddr,
		Ipv4Addr,
		Shutdown,
		SocketAddr,
		TcpListener,
		TcpStream,
		UdpSocket,
	},
	str::from_utf8,
	sync::{
		Arc,
		Mutex,
	},
	thread,
};

use crate::{
	error::*,
	globalstate::*,
	pcap::*,
};

fn handle_command_client(mut command_stream: TcpStream, mut global_state: globalState)
{
	let mut packet_data: [u8; 16192] = [0; 16192];

	loop
	{
		let bytes_received = match command_stream.read(&mut packet_data)
		{
			Ok(v) => v,
			Err(_) =>
			{
				error_and_exit(file!(), line!(), "Failed to receive command");
				return;
			}
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
				return;
			}
		};
	}
}

pub fn command_client_handler(mut global_state: globalState)
{
	let command_listener = match TcpListener::bind("127.0.0.1:81")
	{
		Ok(v) => v,
		Err(_) => panic!("Failed to open command TCP listener."),
	};

	for stream in command_listener.incoming()
	{
		let thread_global_state = global_state.clone();
		let thread = thread::spawn(move || {
			handle_command_client(stream.expect("Connection failed"), thread_global_state);
		});
	}
}

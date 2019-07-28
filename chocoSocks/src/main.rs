pub mod command;
pub mod error;
pub mod globalstate;
pub mod pcap;
pub mod tcpsocks;

use std::{
	fs::File,
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

use crate::{
	command::*,
	error::*,
	globalstate::*,
	pcap::*,
	tcpsocks::*,
};

fn main()
{
	let mut global_state: globalState = globalState::new();

	/* ================== Command listener ================== */

	let global_state_clone = global_state.clone();
	let command_thread = thread::spawn(move || {
		command_client_handler(global_state_clone);
	});

	/* ================== TCP listener ================== */

	let tcp_listener = match TcpListener::bind("127.0.0.1:80")
	{
		Ok(v) => v,
		Err(_) => panic!("Failed to open TCP listener."),
	};

	for stream in tcp_listener.incoming()
	{
		let thread_global_state = global_state.clone();
		let thread = thread::spawn(move || {
			handle_tcp_client(stream.expect("Connection failed"), thread_global_state);
		});
	}

	/* ================== UDP listener ================== */
	/*
		let udp_listener = match UdpSocket::bind("127.0.0.1:81")
		{
			Ok(v) => v,
			Err(_) => panic!("Failed to open UDP listener."),
		};
	*/

	/* ================== Command listener ================== */

	/*
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
	*/
}

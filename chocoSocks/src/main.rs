pub mod command;
pub mod error;
pub mod globalstate;
pub mod pcap;
pub mod tcpsocks;

use std::{
	fs::File,
	env,
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
	
	let str_args : Vec<_> = env::args().collect();
	
	let mut proxy_ip_set : bool = false;
	let mut proxy_port_set : bool = false;
	let mut manager_ip_set : bool = false;
	let mut manager_port_set : bool = false;
	let mut pcap_dir_set : bool = false;
	
	for i in(1..str_args.len()).step_by(2)
	{
		let arg_name = &str_args[i];
		let arg_val = &str_args[i+1];
		
		match arg_name.as_str()
		{
			"--proxy-ip" => proxy_ip_set = true,
			"--proxy-port" => proxy_port_set = true,
			"--manager-ip" => manager_ip_set = true,
			"--manager-port" => manager_port_set = true,
			"--pcap-dir" => pcap_dir_set = true,
			_ => (),
		};
		
		global_state.argv_options.insert(arg_name.clone(), arg_val.clone());
	}
		
	if proxy_ip_set == false || proxy_port_set == false || pcap_dir_set == false
	{
		error_and_exit(file!(), line!(), "Options missing: specify --proxy-ip <ip>, --proxy-port <port>, --manager-ip <ip>, --manager-port <port> and --pcap-dir <path>");
	}
		

	/* ================== Command listener ================== */

	let global_state_clone = global_state.clone();
	let command_thread = thread::spawn(move || {
		command_client_handler(global_state_clone);
	});

	/* ================== TCP listener ================== */

	let tcp_listener = match TcpListener::bind(global_state.argv_options["--proxy-ip"].clone() + &":".to_string() + &global_state.argv_options["--proxy-port"].clone())
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

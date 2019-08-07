extern crate cpython;

pub mod command;
pub mod error;
pub mod globalstate;
pub mod pcap;
pub mod python;
pub mod tcpsocks;
pub mod udpsocks;

use std::{
	env,
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
	python::*,
	tcpsocks::*,
	udpsocks::*,
};

fn main()
{
	let mut global_state: globalState = globalState::new();

	let str_args: Vec<_> = env::args().collect();

	let mut proxy_ip_set: bool = false;
	let mut proxy_port_set: bool = false;
	let mut udp_proxy_ip_set: bool = false;
	let mut udp_proxy_port_set: bool = false;
	let mut manager_ip_set: bool = false;
	let mut manager_port_set: bool = false;
	let mut pcap_dir_set: bool = false;

	for i in (1..str_args.len()).step_by(2)
	{
		let arg_name = &str_args[i];
		let arg_val = &str_args[i + 1];

		match arg_name.as_str()
		{
			"--proxy-ip" => proxy_ip_set = true,
			"--proxy-port" => proxy_port_set = true,
			"--udp-proxy-ip" => udp_proxy_ip_set = true,
			"--udp-proxy-port" => udp_proxy_port_set = true,
			"--manager-ip" => manager_ip_set = true,
			"--manager-port" => manager_port_set = true,
			"--pcap-dir" => pcap_dir_set = true,
			_ => (),
		};

		global_state
			.argv_options
			.insert(arg_name.clone(), arg_val.clone());
	}

	if proxy_ip_set == false
		|| proxy_port_set == false
		|| pcap_dir_set == false
		|| udp_proxy_ip_set == false
		|| udp_proxy_port_set == false
		|| manager_ip_set == false
		|| manager_port_set == false
	{
		error_and_exit(file!(), line!(), "Options missing: specify --proxy-ip <ip>, --proxy-port <port>, --udp-proxy-ip <ip>, --udp-proxy-port <port>, --manager-ip <ip>, --manager-port <port> and --pcap-dir <path>");
	}

	/* ================== Command listener ================== */

	let global_state_clone = global_state.clone();
	let command_thread = thread::spawn(move || {
		command_client_handler(global_state_clone);
	});

	let udp_socks_global_state = global_state.clone();

	let udp_socks_thread = thread::spawn(move || {
		let udp_socks_listener = match TcpListener::bind(
			udp_socks_global_state.argv_options["--udp-proxy-ip"].clone()
				+ &":".to_string()
				+ &udp_socks_global_state.argv_options["--udp-proxy-port"].clone(),
		)
		{
			Ok(v) => v,
			Err(_) => panic!("Failed to open TCP listener for UDP client socks."),
		};

		for stream in udp_socks_listener.incoming()
		{
			let thread_global_state = udp_socks_global_state.clone();
			let thread = thread::spawn(move || {
				handle_udp_client(stream.expect("Connection failed"), thread_global_state);
			});
		}
	});

	/* ================== TCP listener ================== */

	let tcp_listener = match TcpListener::bind(
		global_state.argv_options["--proxy-ip"].clone()
			+ &":".to_string()
			+ &global_state.argv_options["--proxy-port"].clone(),
	)
	{
		Ok(v) => v,
		Err(_) => panic!("Failed to open TCP listener for TCP client socks."),
	};

	for stream in tcp_listener.incoming()
	{
		let thread_global_state = global_state.clone();
		let thread = thread::spawn(move || {
			handle_tcp_client(stream.expect("Connection failed"), thread_global_state);
		});
	}
}

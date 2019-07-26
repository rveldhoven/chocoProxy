use std::{
	io::{Read, Write},
	net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
	str::from_utf8,
	sync::{Arc, Mutex},
	thread,
};

use crate::{error::*, globalstate::*, pcap::*};

fn handle_command_client(
	mut command_stream: TcpStream,
	mut global_state: globalState,
	mut command_state: commandState,
) {
	let mut packet_data: [u8; 16192] = [0; 16192];

	loop {
		let bytes_received = match command_stream.read(&mut packet_data) {
			Ok(v) => v,
			Err(_) => {
				error_and_exit(file!(), line!(), "Failed to receive command");
				return;
			}
		};

		if bytes_received == 0 {
			continue;
		}

		let string_command = match from_utf8(&packet_data[0..bytes_received]) {
			Ok(v) => v,
			_ => {
				error_and_exit(file!(), line!(), "Failed to parse command");
				return;
			}
		};

		let command_global_state = global_state.clone();

		let command_struct: commandStruct = serde_json::from_str(string_command).unwrap();
		match command_struct.command.as_ref() {
			"active_streams" => {
									let mut streams_data = active_streams(command_global_state);
									let mut streams_string = serde_json::to_string(&streams_data).unwrap();
									command_stream.write(&streams_string.len().to_ne_bytes()).unwrap();
									command_stream.write(&streams_string.as_bytes()).unwrap();
								},
			//"repeat_packet" => repeat_packet(command_global_state),
			_ => println!("Unknown command."),
		}
	}
}

pub fn command_client_handler(mut global_state: globalState) {
	let mut command_state: commandState = commandState::new();
	let command_listener = match TcpListener::bind("127.0.0.1:81") {
		Ok(v) => v,
		Err(_) => panic!("Failed to open command TCP listener."),
	};

	for stream in command_listener.incoming() {
		let thread_global_state = global_state.clone();
		let thread_command_state = command_state.clone();
		let thread = thread::spawn(move || {
			handle_command_client(
				stream.expect("Connection failed"),
				thread_global_state,
				thread_command_state,
			);
		});
	}
}

/* ================== Command implementation ================== */

fn active_streams(mut global_state: globalState) -> Vec<streamState>{
	let mut vector_streams : Vec<streamState> = Vec::new();
	if let Ok(mut unlocked_stream) = global_state.tcp_streams.lock() {
		for (_, val) in unlocked_stream.iter() {
			vector_streams.push((*val).clone());
		}
	} else {
		error_and_exit(file!(), line!(), "Failed to lock tcpstreams");
	}
	vector_streams
}

//fn repeat_packet(mut repeater_stream: TcpStream, mut global_state: globalState)
fn repeat_packet(mut global_state: globalState) {}

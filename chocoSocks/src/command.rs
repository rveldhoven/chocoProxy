use std::{
	collections::{
		hash_map::Entry,
		HashMap,
		VecDeque,
	},
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

const GLOBAL_STREAM: &str = "Global";

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

		let command_global_state = global_state.clone();

		let command_state: commandState = serde_json::from_str(string_command).unwrap();
		match command_state.command.as_ref()
		{
			"active_streams" =>
			{
				let mut streams_data = active_streams(command_global_state);
				let mut streams_string = serde_json::to_string(&streams_data).unwrap();
				command_stream
					.write(&(streams_string.len() as u32).to_ne_bytes())
					.unwrap();
				command_stream.write(&streams_string.as_bytes()).unwrap();
			}
			"active_udp_streams" =>
			{
				let mut streams_data = active_udp_streams(command_global_state);
				let mut streams_string = serde_json::to_string(&streams_data).unwrap();
				command_stream
					.write(&(streams_string.len() as u32).to_ne_bytes())
					.unwrap();
				command_stream.write(&streams_string.as_bytes()).unwrap();
			}
			"active_scripts" =>
			{
				let mut scripts_data = active_scripts(command_global_state);
				let mut scripts_string = serde_json::to_string(&scripts_data).unwrap();
				command_stream
					.write(&(scripts_string.len() as u32).to_ne_bytes())
					.unwrap();
				command_stream.write(&scripts_string.as_bytes()).unwrap();
			}
			"delete_script" =>
			{
				delete_script(command_global_state, command_state.parameters);

				debug_print(file!(), line!(), "Handle delete script command");
			}
			"insert_script" =>
			{
				insert_script(command_global_state, command_state.parameters);

				debug_print(file!(), line!(), "Handle insert script command");
			}
			"repeat_packet" =>
			{
				repeat_packet(command_global_state, command_state.parameters);

				debug_print(file!(), line!(), "Handle repeat packet command");
			}
			"toggle_intercept" =>
			{
				toggle_intercept(command_global_state, command_state.parameters);

				debug_print(file!(), line!(), "Handle local intercept command");
			}
			"global_intercept" =>
			{
				global_intercept(command_global_state, command_state.parameters);

				debug_print(file!(), line!(), "Handle global intercept command");
			}
			_ => println!("Unknown command."),
		}
	}
}

pub fn command_client_handler(mut global_state: globalState)
{
	let command_listener = match TcpListener::bind(
		global_state.argv_options["--manager-ip"].clone()
			+ &":".to_string()
			+ &global_state.argv_options["--manager-port"].clone(),
	)
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

/* ================== Command implementation ================== */

fn active_streams(mut global_state: globalState) -> Vec<streamState>
{
	let mut vector_streams: Vec<streamState> = Vec::new();
	if let Ok(mut unlocked_stream) = global_state.tcp_streams.lock()
	{
		for (_, val) in unlocked_stream.iter()
		{
			vector_streams.push((*val).clone());
		}
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock tcpstreams");
	}
	vector_streams
}

fn active_udp_streams(mut global_state: globalState) -> Vec<udpStreamState>
{
	let mut vector_streams: Vec<udpStreamState> = Vec::new();
	if let Ok(mut unlocked_stream) = global_state.udp_streams.lock()
	{
		for (_, val) in unlocked_stream.iter()
		{
			vector_streams.push((*val).clone());
		}
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock tcpstreams");
	}
	vector_streams
}

fn active_scripts(mut global_state: globalState) -> HashMap<String, HashMap<String, pythonScript>>
{
	let mut vector_scripts: HashMap<String, HashMap<String, pythonScript>> = HashMap::new();

	if let Ok(mut unlocked_scripts) = global_state.python_scripts.lock()
	{
		vector_scripts = unlocked_scripts.clone();
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock scripts");
	}

	if let Ok(mut unlocked_global_scripts) = global_state.global_python_scripts.lock()
	{
		vector_scripts.insert(GLOBAL_STREAM.to_string(), unlocked_global_scripts.clone());
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock scripts");
	}

	vector_scripts
}

fn delete_script(mut global_state: globalState, mut parameters: Vec<Vec<u8>>)
{
	if parameters.len() != 2
	{
		error_and_continue(
			file!(),
			line!(),
			"Invalid command: invalid number of parameters",
		);
		return;
	}

	let stream_name: String =
		String::from_utf8(parameters[0].clone()).expect("Invalid UTF8 in stream ID.");
	let script_name: String =
		String::from_utf8(parameters[1].clone()).expect("Invalid UTF8 in stream ID.");

	if stream_name != GLOBAL_STREAM
	{
		delete_script_stream(global_state, stream_name, script_name);
	}
	else
	{
		delete_script_global(global_state, script_name);
	}
}

fn delete_script_global(mut global_state: globalState, script_name: String)
{
	if let Ok(mut locked_scripts) = global_state.global_python_scripts.lock()
	{
		locked_scripts.remove(&script_name);
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock scripts");
	}
}

fn delete_script_stream(mut global_state: globalState, stream_name: String, script_name: String)
{
	if let Ok(mut locked_scripts) = global_state.python_scripts.lock()
	{
		match locked_scripts.entry(stream_name)
		{
			Entry::Occupied(mut o) => o.get_mut().remove(&script_name),
			Entry::Vacant(_) => None,
		};
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock scripts");
	}
}

fn insert_script(mut global_state: globalState, mut parameters: Vec<Vec<u8>>)
{
	if parameters.len() != 4
	{
		error_and_continue(
			file!(),
			line!(),
			"Invalid command: invalid number of parameters",
		);
		return;
	}

	let stream_name: String =
		String::from_utf8(parameters[0].clone()).expect("Invalid UTF8 in stream ID.");
	let script_name: String =
		String::from_utf8(parameters[1].clone()).expect("Invalid UTF8 in stream ID.");
	let script_direction: String =
		String::from_utf8(parameters[2].clone()).expect("Invalid UTF8 in stream ID.");
	let script_content: String =
		String::from_utf8(parameters[3].clone()).expect("Invalid UTF8 in stream ID.");

	if stream_name != GLOBAL_STREAM
	{
		insert_script_stream(
			global_state,
			stream_name,
			script_name,
			script_direction,
			script_content,
		);
	}
	else
	{
		insert_script_global(global_state, script_name, script_direction, script_content);
	}
}

fn insert_script_stream(
	mut global_state: globalState,
	stream_name: String,
	script_name: String,
	script_direction: String,
	script_content: String,
)
{
	if let Ok(mut locked_scripts) = global_state.python_scripts.lock()
	{
		match locked_scripts.entry(stream_name)
		{
			Entry::Occupied(mut o) => o.get_mut().insert(
				script_name,
				pythonScript::new(script_direction, script_content),
			),
			Entry::Vacant(_) => None,
		};
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock scripts");
	}
}

fn insert_script_global(
	mut global_state: globalState,
	script_name: String,
	script_direction: String,
	script_content: String,
)
{
	if let Ok(mut locked_scripts) = global_state.global_python_scripts.lock()
	{
		locked_scripts.insert(
			script_name,
			pythonScript::new(script_direction, script_content),
		);
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock scripts");
	}
}

fn repeat_packet(mut global_state: globalState, mut parameters: Vec<Vec<u8>>)
{
	let stream_id: String =
		String::from_utf8(parameters[0].clone()).expect("Invalid UTF8 in stream ID.");
	parameters.remove(0);
	let command_data = commandState::new(String::from("repeat_packet"), parameters);

	if let Ok(mut unlocked_command) = global_state.commands.lock()
	{
		let mut hashentry = unlocked_command.entry(stream_id).or_insert(VecDeque::new());
		hashentry.push_back(command_data);
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock commands");
	}
}

fn toggle_intercept(mut global_state: globalState, mut parameters: Vec<Vec<u8>>)
{
	let stream_id: String =
		String::from_utf8(parameters[0].clone()).expect("Invalid UTF8 in stream ID.");
	parameters.remove(0);
	let command_data = commandState::new(String::from("toggle_intercept"), parameters);

	if let Ok(mut unlocked_command) = global_state.commands.lock()
	{
		let mut hashentry = unlocked_command.entry(stream_id).or_insert(VecDeque::new());
		hashentry.push_back(command_data);
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock commands.");
	}
}

fn global_intercept(mut global_state: globalState, mut parameters: Vec<Vec<u8>>)
{
	if let Ok(mut unlocked_toggle) = global_state.global_intercept.lock()
	{
		let toggle_flag: String =
			String::from_utf8(parameters[0].clone()).expect("Invalid UTF8 in global toggle flag.");
		let mut unlocked_toggle = match toggle_flag.as_ref()
		{
			"true" => true,
			"false" => false,
			_ => panic!("Invalid value for global intercept mutex - must be true or false."),
		};
	}
	else
	{
		error_and_exit(file!(), line!(), "Failed to lock global intercept mutex.");
	}
}

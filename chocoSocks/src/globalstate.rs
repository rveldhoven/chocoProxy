use std::{
	collections::HashMap,
	sync::{
		Arc,
		Mutex,
	},
};

use crate::error::*;
use serde::{
	Deserialize,
	Serialize,
};
use serde_json::Result;

const both_stream_direction: &str = "Both";
const server_stream_direction: &str = "ServerClient";
const client_stream_direction: &str = "ClientServer";

/* ================== Connection global state ================== */

#[repr(C)]
#[derive(Serialize, Deserialize, Clone)]
pub struct streamState
{
	destination_ip: String,
	destination_port: String,
	source_ip: String,
	source_port: String,
	source_process_pid: String,
	source_process_name: String,
	backend_file: String,
	proxy_connected: bool,
	stream_start: String,
}

impl streamState
{
	pub fn new(
		destination_ip: String,
		destination_port: String,
		source_ip: String,
		source_port: String,
		source_process_pid: String,
		source_process_name: String,
		backend_file: String,
		proxy_connected: bool,
		stream_start: String,
	) -> streamState
	{
		streamState {
			destination_ip,
			destination_port,
			source_ip,
			source_port,
			source_process_pid,
			source_process_name,
			backend_file,
			proxy_connected,
			stream_start,
		}
	}
}

/* ================== Command global state ================== */

#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct commandState
{
	pub command: String,
	pub parameters: Vec<Vec<u8>>,
}

impl commandState
{
	pub fn new(command: String, parameters: Vec<Vec<u8>>) -> commandState
	{
		commandState {
			command,
			parameters,
		}
	}
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone)]
pub struct pythonScript
{
	pub direction: String,
	pub script: String,
}

impl pythonScript
{
	pub fn new(adirection: String, ascript: String) -> pythonScript
	{
		if adirection != both_stream_direction.to_string()
			&& adirection != client_stream_direction.to_string()
			&& adirection != server_stream_direction.to_string()
		{
			error_and_exit(file!(), line!(), "Invalid stream direction");
		}

		pythonScript {
			script: ascript,
			direction: adirection,
		}
	}
}

#[derive(Clone)]
pub struct globalState
{
	pub tcp_streams: Arc<Mutex<HashMap<String, streamState>>>,
	pub commands: Arc<Mutex<HashMap<String, commandState>>>,
	pub python_scripts: Arc<Mutex<HashMap<String, HashMap<String, pythonScript>>>>,
	pub global_python_scripts: Arc<Mutex<HashMap<String, pythonScript>>>,
	pub argv_options: HashMap<String, String>,
}

impl globalState
{
	pub fn new() -> globalState
	{
		globalState {
			tcp_streams: Arc::new(Mutex::new(HashMap::new())),
			commands: Arc::new(Mutex::new(HashMap::new())),
			python_scripts: Arc::new(Mutex::new(HashMap::new())),
			global_python_scripts: Arc::new(Mutex::new(HashMap::new())),
			argv_options: HashMap::new(),
		}
	}
}

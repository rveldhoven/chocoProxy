use std::{
	collections::HashMap,
	sync::{
		Arc,
		Mutex,
	},
};

use serde::{Deserialize, Serialize};
use serde_json::Result;

/* ================== Connection global state ================== */

#[repr(C)]
pub struct streamState
{
	destination_ip: String,
	destination_port: String,
	source_ip: String,
	source_port: String,
	source_process_pid: String,
	source_process_name: String,
	backend_file: String,
	stream_start: String,
	proxy_connected: String,
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
		stream_start: String,
		proxy_connected: String,
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
			stream_start,
			proxy_connected,
		}
	}
}

#[derive(Clone)]
pub struct globalState
{
	pub tcp_streams: Arc<Mutex<HashMap<String, streamState>>>,
}

impl globalState
{
	pub fn new() -> globalState
	{
		globalState {
			tcp_streams: Arc::new(Mutex::new(HashMap::new())),
		}
	}
}

/* ================== Command global state ================== */

#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct commandStruct
{
	pub command: String,
	params: Vec<Vec<u8>>,
}

impl commandStruct
{
	pub fn new(
		command: String,
		params: Vec<Vec<u8>>,
	) -> commandStruct
	{
		commandStruct {
			command,
			params,
		}
	}
}

#[derive(Clone)]
pub struct commandState
{
	pub commands: Arc<Mutex<HashMap<String, commandStruct>>>,
}

impl commandState
{
	pub fn new() -> commandState
	{
		commandState {
			commands: Arc::new(Mutex::new(HashMap::new())),
		}
	}
}
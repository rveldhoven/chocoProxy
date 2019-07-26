use std::{
	collections::HashMap,
	sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use serde_json::Result;
use crate::error::*;

/* ================== Connection global state ================== */

#[repr(C)]
#[derive(Serialize, Deserialize, Clone)]
pub struct streamState {
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

impl streamState {
	pub fn new(
		destination_ip: String,
		destination_port: String,
		source_ip: String,
		source_port: String,
		source_process_pid: String,
		source_process_name: String,
		backend_file: String,
		proxy_connected: bool,
		stream_start: String
	) -> streamState {
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

#[derive(Clone)]
pub struct globalState {
	pub tcp_streams: Arc<Mutex<HashMap<String, streamState>>>,
}

impl globalState {
	pub fn new() -> globalState {
		globalState {
			tcp_streams: Arc::new(Mutex::new(HashMap::new())),
		}
	}
}

/* ================== Command global state ================== */

#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct commandStruct {
	pub command: String,
	parameters: Vec<Vec<u8>>,
}

impl commandStruct {
	pub fn new(command: String, parameters: Vec<Vec<u8>>) -> commandStruct {
		commandStruct { command, parameters }
	}
}

#[derive(Clone)]
pub struct commandState {
	pub commands: Arc<Mutex<HashMap<String, commandStruct>>>,
}

impl commandState {
	pub fn new() -> commandState {
		commandState {
			commands: Arc::new(Mutex::new(HashMap::new())),
		}
	}
}

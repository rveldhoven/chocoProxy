
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;


/* ================== Global state ================== */

#[repr(C)]
struct streamState
{
	destination_ip : String,
	destination_port : String,
	source_ip: String,
	source_port : String,
	source_process_pid : String,
	source_process_name : String,
	backend_file : String,
	stream_start : String,
	proxy_connected : String
}

impl streamState
{
	pub fn new(destination_ip : String, destination_port : String, source_ip: String, source_port : String, source_process_pid : String, source_process_name : String, backend_file : String, stream_start : String, proxy_connected : String) -> streamState
	{
		streamState
		{
			destination_ip,
			destination_port,
			source_ip,
			source_port,
			source_process_pid,
			source_process_name,
			backend_file,
			stream_start,
			proxy_connected
		}
	}
}

#[derive(Clone)]
pub struct globalState
{
	tcp_streams : Arc<Mutex<HashMap<String, streamState>>>,
}

impl globalState
{
	pub fn new() -> globalState
	{
		globalState { tcp_streams : Arc::new(Mutex::new(HashMap::new())) }
	}
}
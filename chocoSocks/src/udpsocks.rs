use std::{
	fs::{
		File,
		OpenOptions,
	},
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

use std::os::windows::fs::OpenOptionsExt;

const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const FILE_SHARE_DELETE: u32 = 4;

use crate::{
	command::*,
	error::*,
	globalstate::*,
	pcap::*,
	python::*,
};

#[repr(C)]
struct UDPRequest
{
	request_mode: u8,
	dest_ipv4_ip: Ipv4Addr,
	dest_udp_port : u16,
}

impl UDPRequest
{
	fn create_from_bytes(bytes: &[u8]) -> UDPRequest
	{
		let mut port: [u8; 2] = [0; 2];

		port.copy_from_slice(&bytes[5..7]);

		// parse bytes
		UDPRequest {
			request_mode: bytes[0],
			dest_ipv4_ip : Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]),
			dest_udp_port: unsafe { transmute::<[u8; 2], u16>(port) }.to_be(),
		}
	}
}

#[repr(C)]
struct UDPResponse
{
	src_ipv4_ip : u32,
	src_udp_port : u16,
}

pub fn receive_packet_from_client(client_stream : &mut TcpStream) -> Vec<u8>
{
	let mut bytes_receive_size : [u8; 4] = [0; 4];
	if let Err(_) = client_stream.read(&mut bytes_receive_size)
	{
		error_and_exit(file!(), line!(), "Failed to receive intercepted packet length.");
	}
	
	let mut intercept_amount = unsafe { 
		std::mem::transmute::<[u8; 4], u32>(
		[bytes_receive_size[0], bytes_receive_size[1], bytes_receive_size[2], bytes_receive_size[3]]
		)}.to_le();
		
	println!("UDP socks: receiving: {} bytes", intercept_amount);
		
	let mut result_bytes : Vec<u8> = Vec::with_capacity(intercept_amount as usize);
	
	if let Err(_) = client_stream.read(&mut result_bytes)
	{
		error_and_exit(file!(), line!(), "Failed to receive intercepted packet.");
	}
	
	result_bytes
}

pub fn handle_udp_client(mut client_stream: TcpStream, mut global_state: globalState)
{
	let mut packet_bytes = Vec::new();
	let mut request_struct = UDPRequest
	{ 
		request_mode: 0,
		dest_ipv4_ip: IpAddr::new(0,0,0,0),
		dest_udp_port: 0,
	}

	loop
	{
		packet_bytes = receive_packet_from_client(&mut client_stream);
		request_struct = UDPRequest::create_from_bytes(&packet_bytes[0..7]);
		packet_bytes = packet_bytes[7..].to_vec();
		
		
		
		
	}
}




















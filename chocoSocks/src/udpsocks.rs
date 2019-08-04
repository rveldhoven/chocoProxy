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
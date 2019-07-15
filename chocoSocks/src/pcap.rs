use std::io::Write;
use std::thread;
use std::fs::File;
use std::io::Error;
use std::convert::TryInto;
use std::time::{UNIX_EPOCH, SystemTime};

use crate::error::*;

/* ================== Global Header ================== */

#[repr(C)]
pub struct globalHeader
{
	magic_number : u32, 
	major_version : u16, 
	minor_version : u16, 
	thiszone : i32, 
	sigfigs : u32, 
	snaplen : u32, 
	network : u32,
}

impl globalHeader
{
	pub fn create_header() -> globalHeader
	{
		globalHeader
		{
			magic_number : 0xa1b2c3d4,
			major_version : 2,
			minor_version : 4,
			thiszone : 0,
			sigfigs : 0,
			snaplen : 65535,
			network : 0,
		}
	}
}

/* ================== Ethernet Header ================== */

#[repr(C)]
pub struct ethernetHeader
{
	ether_dhost : [u8;6],
	ether_shost : [u8;6],
	ether_type : u16,
}

impl ethernetHeader
{
	pub fn create_header() -> ethernetHeader
	{
		ethernetHeader {
			ether_dhost : [0xff,0xff,0xff,0xff,0xff,0xff],
			ether_shost : [0x00,0x00,0x00,0x00,0x00,0x00],
			ether_type : 0,
		}
	}
}

/* ================== IP Header ================== */

#[repr(C)]
pub struct ipHeader
{
	ip_vhl : u8, 
	ip_tos : u8, 
	ip_len : u16, 
	ip_id : u16, 
	ip_flagplusoff : u16,
	ip_ttl : u8, 
	ip_proto : u8, 
	ip_hsum : u8, 
	ip_src : u32,
	ip_dst : u32,
}

impl ipHeader
{
	pub fn create_header(source_ip : u32, dest_ip :u32, packet_size : u16) -> ipHeader
	{
		ipHeader
		{
			ip_vhl : 0x45,
			ip_tos : 0x00,
			ip_len : packet_size,
			ip_id : 0x0000,
			ip_flagplusoff : 0x0000,
			ip_ttl : 0x00,
			ip_proto : 0x00,
			ip_hsum : 0x00,
			ip_src : source_ip,
			ip_dst : dest_ip,
		}
	}
}

/* ================== Transport Header ================== */
#[repr(C)]
pub struct tcpHeader
{
    source_port: u16,
    destination_port: u16,
    seq: u32,
    ack: u32,
    off_res_flags: u16,
    win_size: u16,
    checksum: u16,
    urgent: u16
}

impl tcpHeader
{
	pub fn create_header(source_port: u16, destination_port: u16, seq: u32, win: u16) -> tcpHeader
	{
		tcpHeader
		{
			source_port,
			destination_port,
			seq,
			ack: 0,
			off_res_flags : 0,
			win_size : win,
			checksum: 0,
			urgent: 0,
		}
	}
}

#[repr(C)]
pub struct pcapPacket
{
	ts_sec : u32,
	ts_usec : u32,
	incl_len : u32,
	orig_len : u32,
	data : Vec <u8>,
}

impl pcapPacket
{
	pub fn create_from_bytes(bytes : &[u8]) -> pcapPacket
	{
		let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
		pcapPacket 
		{
			ts_sec : current_time.as_secs() as u32,
			ts_usec : current_time.subsec_micros(),
			incl_len : bytes.len() as u32,
			orig_len : bytes.len() as u32,
			data : bytes.to_vec(),
		}
	}
}

pub fn save_to_pcap(packet: &pcapPacket, syn_number : u32, file: &mut File) -> std::io::Result<()>
{
	let eth = ethernetHeader::create_header();
	let ip = ipHeader::create_header(0, 1, (std::mem::size_of::<ipHeader>() + std::mem::size_of::<tcpHeader>() + packet.data.len()).try_into().unwrap() );
	let tcp = tcpHeader::create_header(0, 1, syn_number, 64000);
	
	let ether_data = unsafe{ any_as_u8_slice(&eth) };
	let ip_data = unsafe{ any_as_u8_slice(&ip) };
	let tcp_data = unsafe{ any_as_u8_slice(&tcp) };

	let mut data = Vec::new();
	
	data.extend_from_slice(ether_data);
	data.extend_from_slice(ip_data);
	data.extend_from_slice(tcp_data);
	data.extend_from_slice(&packet.data[..]);

	let real_packet = pcapPacket::create_from_bytes(&data[..]);
	
	let final_data = unsafe{ any_as_u8_slice(&real_packet) };
	
	if let Err(_) = file.write(&final_data)
	{
		error_and_exit(file!(), line!(), "Failed to append pcap data to pcap");
	}
	
	if let Err(_) = file.flush() // pub fn error_and_exit(file : String, line : u32, message : String) 
	{
		error_and_exit(file!(), line!(), "Failed to append pcap data to pcap");
	}

	Ok(())
}

pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] 
{
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}

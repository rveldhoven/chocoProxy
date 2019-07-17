use std::io::Write;
use std::fs::File;
use std::convert::TryInto;
use std::time::{UNIX_EPOCH, SystemTime};

use crate::error::*;

const MAX_TPC_PACKET_PAYLOAD : usize = 65535;

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
			network : 1,
		}
	}
}

/* ================== Ethernet Header ================== */

#[repr(C)]
pub struct ethernetHeader
{
	ether_dhost : [u8;6],
	ether_shost : [u8;6],
	ether_type :  [u8;2],
}

impl ethernetHeader
{
	pub fn create_header() -> ethernetHeader
	{
		ethernetHeader {
			ether_dhost : [0xff,0xff,0xff,0xff,0xff,0xff],
			ether_shost : [0x00,0x00,0x00,0x00,0x00,0x00],
			ether_type : [0x08, 0x00],
		}
	}
}

/* ================== IP Header ================== */

#[repr(C)] //  20 bytes
pub struct ipHeader  
{
	ip_vhl : u8, 
	ip_tos : u8, 
	ip_len : u16, 
	ip_id : u16, 
	ip_flagplusoff : u16,
	ip_ttl : u8, 
	ip_proto : u8, 
	ip_hsum : u16, 
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
			ip_len : packet_size.to_be(),
			ip_id : 0x0000,
			ip_flagplusoff : 0x0000,
			ip_ttl : 0xfe,
			ip_proto : 0x06,
			ip_hsum : 0x0000,
			ip_src : source_ip,
			ip_dst : dest_ip,
		}
	}
}

/* ================== Transport Header ================== */
#[repr(C)] // 20 bytes
pub struct tcpHeader
{
    th_sport: u16,
    th_dport: u16,
    th_seq: u32,
    th_ack: u32,
	th_off : u8,
    th_flags: u8,
    th_win: u16,
    th_sum: u16,
    th_urp: u16
}

impl tcpHeader
{
	pub fn create_header_syn(source_port: u16, destination_port: u16, seq: &u32, ack : &u32, win: u16) -> tcpHeader
	{
		tcpHeader
		{
			th_sport : source_port,
			th_dport : destination_port,
			th_seq : (*seq).to_be(),
			th_ack: (*ack).to_be(),
			th_off : 0x50,
			th_flags : 0x10, // 0x18
			th_win : win,
			th_sum: 0,
			th_urp: 0,
		}
	}
	
	pub fn create_header_ack(source_port: u16, destination_port: u16, seq: &u32, ack : &u32, win: u16) -> tcpHeader
	{
		tcpHeader
		{
			th_sport : source_port,
			th_dport : destination_port,
			th_seq : (*seq).to_be(),
			th_ack: (*ack).to_be(),
			th_off : 0x50,
			th_flags : 0x10,
			th_win : win,
			th_sum: 0,
			th_urp: 0,
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
		}
	}
}

fn emit_syn(packet_data : &Vec<u8>, src : &u32, dst : &u32, a_syn : &u32,  b_syn : &u32, file: &mut File)
{	
	let header_length = std::mem::size_of::<ipHeader>() + std::mem::size_of::<tcpHeader>();
	let packet_length = header_length + packet_data.len();
	
	let mut dport = 1;
	let mut sport = 0;
	
	if *src == 0
	{
		dport = 0;
		sport = 1;
	}
	
	let eth = ethernetHeader::create_header();
	let ip = ipHeader::create_header(*src, *dst, packet_length.try_into().unwrap() );
	let tcp = tcpHeader::create_header_syn(sport, dport, a_syn, b_syn, 64000);
	
	let ether_data = unsafe{ any_as_u8_slice(&eth) };
	let ip_data = unsafe{ any_as_u8_slice(&ip) };
	let tcp_data = unsafe{ any_as_u8_slice(&tcp) };

	let mut data = Vec::new();
	
	data.extend_from_slice(ether_data);
	data.extend_from_slice(ip_data);
	data.extend_from_slice(tcp_data);
	data.extend_from_slice(&packet_data[..]);

	let real_packet = pcapPacket::create_from_bytes(&data[..]);
	
	let pcap_header_bytes = unsafe{ any_as_u8_slice(&real_packet) };
	
	if let Err(_) = file.write(&pcap_header_bytes)
	{
		error_and_exit(file!(), line!(), "Failed to append pcap data to pcap");
	}
	
	if let Err(_) = file.write(&data[..])
	{
		error_and_exit(file!(), line!(), "Failed to append pcap data to pcap");
	}
	
	if let Err(_) = file.flush() 
	{
		error_and_exit(file!(), line!(), "Failed to append pcap data to pcap");
	}
}

fn emit_ack(packet_data : &Vec<u8>, src : &u32, dst : &u32, a_syn : &u32,  b_syn : &u32, file: &mut File)
{
	let ack_number : u32 = *a_syn + packet_data.len() as u32;
	
	let mut dport = 1;
	let mut sport = 0;
	
	if *src == 0
	{
		dport = 0;
		sport = 1;
	}
	
	let eth = ethernetHeader::create_header();
	let ip = ipHeader::create_header(*src, *dst, (std::mem::size_of::<ipHeader>() + std::mem::size_of::<tcpHeader>()).try_into().unwrap() );
	let tcp = tcpHeader::create_header_ack(sport, dport, b_syn, &ack_number, 64000);
	
	let ether_data = unsafe{ any_as_u8_slice(&eth) };
	let ip_data = unsafe{ any_as_u8_slice(&ip) };
	let tcp_data = unsafe{ any_as_u8_slice(&tcp) };

	let mut data = Vec::new();
	
	data.extend_from_slice(ether_data);
	data.extend_from_slice(ip_data);
	data.extend_from_slice(tcp_data);

	let real_packet = pcapPacket::create_from_bytes(&data[..]);
	
	let pcap_header_bytes = unsafe{ any_as_u8_slice(&real_packet) };
	
	if let Err(_) = file.write(&pcap_header_bytes)
	{
		error_and_exit(file!(), line!(), "Failed to append pcap data to pcap");
	}
	
	if let Err(_) = file.write(&data[..])
	{
		error_and_exit(file!(), line!(), "Failed to append pcap data to pcap");
	}
	
	if let Err(_) = file.flush() 
	{
		error_and_exit(file!(), line!(), "Failed to append pcap data to pcap");
	}
}

pub fn save_to_pcap(packet_data : &Vec<u8>, src : &u32, dst : &u32, a_syn : &u32,  b_syn : &u32, file: &mut File)
{
	let num_packets = packet_data.len() / MAX_TPC_PACKET_PAYLOAD;
	let last_packet_size = packet_data.len() % MAX_TPC_PACKET_PAYLOAD;
	
	for i in 0..num_packets
	{
		let mut current_packet = Vec::new();
		
		current_packet.extend_from_slice(&packet_data[(i*MAX_TPC_PACKET_PAYLOAD)..((i+1)*MAX_TPC_PACKET_PAYLOAD)]);
	
		emit_syn(&current_packet, src, dst, a_syn, b_syn, file);

		emit_ack(&current_packet, dst, src, a_syn, b_syn, file);
	}
	
	if last_packet_size != 0
	{
		let mut current_packet = Vec::new();
		
		current_packet.extend_from_slice(&packet_data[0..last_packet_size]);
	
		emit_syn(&current_packet, src, dst, a_syn, b_syn, file);

		emit_ack(&current_packet, dst, src, a_syn, b_syn, file);
	}
}

pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] 
{
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}

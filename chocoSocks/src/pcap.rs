use std::io::Write;
use std::thread;
use std::fs::File;
use std::io::Error;
use std::time::{UNIX_EPOCH, SystemTime};

#[repr(C)]
pub struct globalHeader
{
	magic_number : u32, // 0xa1b2c3d4,
	major_version : u16, // 2
	minor_version : u16, // 4,
	thiszone : i32, // 0
	sigfigs : u32, // 0
	snaplen : u32, // 65535
	network : u32, // 0
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
		pcapPacket {
			ts_sec : current_time.as_secs() as u32,
			ts_usec : current_time.subsec_micros(),
			incl_len : bytes.len() as u32,
			orig_len : bytes.len() as u32,
			data : bytes.to_vec(),
		}
	}
}

pub fn save_to_pcap(packet: &pcapPacket, file: &mut File) -> std::io::Result<()>
{
	let packet_data = unsafe{ any_as_u8_slice(packet) };	
	match file.write(packet_data)
	{
		Ok(v) => file.flush(),
		Err(_) =>
			{
				println!("Writing failed");
				return Err(Error::last_os_error());
			},
	};
	Ok(())
}

pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] 
{
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}

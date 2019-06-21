use std::io::Write;
use std::thread;
use std::fs::File;

#[repr(C)]
struct globalHeader
{
	magic_number : u32, // 0xa1b2c3d4,
	major_version : u16, // 2
	minor_version : u16, // 4,
	thiszone : i32, // 0
	sigfigs : u32, // 0
	snaplen : u32, // 65535
	network : u32, // 0
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
	pub fn create_from_bytes(time: u32, offset: u32, length: u32, bytes : &Vec <u8>) -> pcapPacket
	{
		pcapPacket {
			ts_sec : time,
			ts_usec : offset,
			incl_len : length,
			orig_len : length,
			data : bytes.clone()
		}
	}
}

pub fn save_to_pcap(packet: &pcapPacket, mut file: File) -> std::io::Result<()>
{
	
	let struct_bytes = unsafe{ any_as_u8_slice(packet) };	
	file.write(struct_bytes)?;
	Ok(())
}

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] 
{
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}


pub fn error_and_exit(file : String, line : u32, message : String) 
{
	println!("{}", "Error in: ".to_string() + &file + " ".to_string() + &line.to_string() + " ".to_string() + &message);
	panic!("Error in: ".to_string() + file + " ".to_string() + line.to_string() + " ".to_string() + message);
}
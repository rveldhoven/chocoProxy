pub fn error_and_exit(file: &str, line: u32, message: &str)
{
	println!(
		"{}",
		"Error in: ".to_string()
			+ &file.to_string()
			+ &" ".to_string()
			+ &line.to_string()
			+ &" ".to_string()
			+ &message.to_string()
	);
	panic!(
		"Error in: ".to_string()
			+ &file.to_string()
			+ &" ".to_string()
			+ &line.to_string()
			+ &" ".to_string()
			+ &message.to_string()
	);
}

pub fn error_and_continue(file: &str, line: u32, message: &str)
{
	println!(
		"{}",
		"Error in: ".to_string()
			+ &file.to_string()
			+ &" ".to_string()
			+ &line.to_string()
			+ &" ".to_string()
			+ &message.to_string()
	);
}

pub fn debug_print(file: &str, line: u32, message: &str)
{
	#[cfg(debug_assertions)]
	println!(
		"{}",
		"Info in: ".to_string()
			+ &file.to_string()
			+ &" ".to_string()
			+ &line.to_string()
			+ &" ".to_string()
			+ &message.to_string()
	);
}

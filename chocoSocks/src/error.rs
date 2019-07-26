pub fn error_and_exit(file: &str, line: u32, message: &str) {
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

use cpython::{
	ObjectProtocol,
	PyModule,
	PyResult,
	Python,
};

const MODULE_NAME : &str = "choco_python";
const FUNCTION_NAME : &str = "handle_packet";

fn python_handler_from_str(py: Python<'_>, name: &String, source: &String) -> PyResult<PyModule>
{
	let m = PyModule::new(py, name)?;

	let builtins = cpython::PyModule::import(py, "builtins").unwrap();
	m.dict(py).set_item(py, "__builtins__", &builtins).unwrap();

	// OR
	m.add(py, "__builtins__", py.import("builtins")?)?;
	let m_locals = m.get(py, "__dict__")?.extract(py)?;

	// To avoid multiple import, and to add entry to the cache in `sys.modules`.
	let sys = cpython::PyModule::import(py, "sys").unwrap();
	sys.get(py, "modules")
		.unwrap()
		.set_item(py, name, &m)
		.unwrap();

	// Finally, run the moduke
	py.run(source, Some(&m_locals), None)?;
	Ok(m)
}

pub fn execute_python_handler(
	python_script: &String,
	source_ip: &String,
	dest_ip: &String,
	packet_type: &String,
	packet_src_port: &String,
	packet_dst_port: &String,
	packet_payload: Vec<u8>,
) -> Result<Vec<u8>, ()>
{
	// module_from_str(py, "fibo", FIBO_PY)?;
	
    let gil = Python::acquire_gil();
    let py = gil.python();

	let mut result_bytes = Vec::new();

	let packet_module = match python_handler_from_str(py, &MODULE_NAME.to_string(), python_script)
	{
		Ok(v) => v,
		_ => return Err(()),
	};
	
	let result = match packet_module.call(py, FUNCTION_NAME, (source_ip, dest_ip, packet_type, packet_src_port, packet_dst_port, packet_payload,), None)
	{
		Ok(v) => v,
		_ => return Err(()),
	};
	
	result_bytes = match result.extract(py)
	{
		Ok(v) => v,
		_ => return Err(()),
	};
	
	Ok(result_bytes)
}

pub fn execute_python_handlers(
	python_scripts: Vec<String>,
	source_ip: &String,
	dest_ip: &String,
	packet_type: &String,
	packet_src_port: &String,
	packet_dst_port: &String,
	packet_payload: Vec<u8>,
) -> Result<Vec<u8>, ()>
{
	let mut result_bytes = packet_payload.clone();

	for string_handler in python_scripts.iter()
	{
		result_bytes = match execute_python_handler(
			string_handler,
			source_ip,
			dest_ip,
			packet_type,
			packet_src_port,
			packet_dst_port,
			result_bytes,
		)
		{
			Ok(v) => v,
			_ => return Err(()),
		};
	}

	Ok(result_bytes)
}

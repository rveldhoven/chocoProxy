#include "x64_hook.hpp"

#include <Windows.h>

uint64_t qword_abs(uint64_t a, uint64_t b)
{
	return a < b ? b - a : a - b;
}

bool cx64PrologueHook::_hook_is_code_cave_valid()
{
	if (qword_abs(_code_cave_location, _hook_location) > 0xffffffff)
		return false;

	return true;
}

void cx64PrologueHook::_hook_set_trampoline()
{
	std::vector<uint8_t> trampoline_code;

	trampoline_code.push_back(0x48);
	trampoline_code.push_back(0xb8);
	trampoline_code.insert(trampoline_code.end(), (uint8_t*)&_hook_destination, (uint8_t*)&_hook_destination + sizeof(_hook_destination));
	trampoline_code.push_back(0xff);

	if(_hook_is_call_type == true)
		trampoline_code.push_back(0xd0);
	else
		trampoline_code.push_back(0xe0);

	_hook_trampoline_end = _code_cave_location + trampoline_code.size();

	trampoline_code.insert(trampoline_code.end(), _displaced_instruction.begin(), _displaced_instruction.end());

	uint64_t from_location = _code_cave_location + trampoline_code.size();
	uint64_t to_location = _hook_location + _displaced_instruction.size();
	uint32_t return_jump_displacement = to_location - from_location - 0x5;

	trampoline_code.push_back(0xe9);
	trampoline_code.insert(trampoline_code.end(), (uint8_t*)&return_jump_displacement, (uint8_t*)&return_jump_displacement + sizeof(return_jump_displacement));

	DWORD Dummy = 0, Dummy2 = 0;

	VirtualProtect((void*)_code_cave_location, trampoline_code.size(), 0x40, &Dummy);

	memcpy((void*)_code_cave_location, trampoline_code.data(), trampoline_code.size());

	VirtualProtect((void*)_code_cave_location, trampoline_code.size(), Dummy, &Dummy2);

	_trampoline_is_set = true;
}

void cx64PrologueHook::_hook_set_hook()
{
	uint32_t copy_size = 0;

	for (auto& pattern : *_copy_patterns)
	{
		if (memcmp((void*)pattern.first.data(), (void*)_hook_location, pattern.first.size()) == 0)
		{
			copy_size = pattern.second;
			break;
		}
	}

	if (copy_size == 0 || copy_size < 2)
	{
		std::string error_message = "Error: unsupported function prologue: [ ";

		for (int i = 0; i < 0x16; i++)
		{
			char buffer[10] = {};

			sprintf_s(buffer, "%.2x", ((uint8_t*)_hook_location)[i]);

			error_message += std::string(buffer);
		}

		error_message += " ]";

		throw std::runtime_error(error_message);
	}

	_displaced_instruction.resize(copy_size);

	memcpy((void*)_displaced_instruction.data(), (void*)_hook_location, _displaced_instruction.size());

	_hook_set_trampoline();

	uint8_t* start_pointer = (uint8_t*)_hook_location - 0x5;

	if(memcmp((void*)start_pointer, (void*)"\xcc\xcc\xcc\xcc\xcc\xcc", 0x5) != 0)
		throw std::runtime_error("Error: unsupported function prologue");

	std::vector<uint8_t> hook_code;

	uint64_t to_location = _code_cave_location;
	uint64_t from_location = (uint64_t)start_pointer;

	uint32_t jump_displacement = to_location - from_location - 0x5;

	hook_code.push_back(0xe9);
	hook_code.insert(hook_code.end(), (uint8_t*)&jump_displacement, (uint8_t*)&jump_displacement + sizeof(jump_displacement));
	hook_code.push_back(0xeb);
	hook_code.push_back(0xf9);

	for (int i = 0; i < copy_size - 2; i++)
		hook_code.push_back(0x90);

	DWORD Dummy = 0, Dummy2 = 0;

	VirtualProtect((void*)from_location, hook_code.size(), 0x40, &Dummy);

	memcpy((void*)from_location, hook_code.data(), hook_code.size());

	VirtualProtect((void*)from_location, hook_code.size(), Dummy, &Dummy2);

	_hook_is_set = true;
}

cx64PrologueHook::cx64PrologueHook(std::shared_ptr<CopyPatterns> patterns)
	: _copy_patterns(patterns), _hook_location(0), _code_cave_location(0), _hook_destination(0), _hook_is_set(false), _trampoline_is_set(false)
{
}

cx64PrologueHook::~cx64PrologueHook()
{
	if (is_hook_set() == true)
		hook_unset();
}

void cx64PrologueHook::hook_set_trampoline(uint64_t hook_location, uint64_t code_cave, uint64_t hook_destination, bool call_type)
{
	if (_trampoline_is_set == true)
		throw std::runtime_error("Error: trampoline already set");

	_hook_location = hook_location;
	_code_cave_location = code_cave;
	_hook_destination = hook_destination;
	_hook_is_call_type = call_type;

	if (_hook_is_code_cave_valid() == false)
		throw std::runtime_error("Error: code cave is not sufficient");

	uint32_t copy_size = 0;

	for (auto& pattern : *_copy_patterns)
	{
		if (memcmp((void*)pattern.first.data(), (void*)_hook_location, pattern.first.size()) == 0)
		{
			copy_size = pattern.second;
			break;
		}
	}

	if (copy_size == 0 || copy_size < 2)
	{
		std::string error_message = "Error: unsupported function prologue: [ ";

		for (int i = 0; i < 0x16; i++)
		{
			char buffer[10] = {};

			sprintf_s(buffer, "%.2x", ((uint8_t*)_hook_location)[i]);

			error_message += std::string(buffer);
		}

		error_message += " ]";

		throw std::runtime_error(error_message);
	}


	_displaced_instruction.resize(copy_size);

	memcpy((void*)_displaced_instruction.data(), (void*)_hook_location, _displaced_instruction.size());

	_hook_set_trampoline();
}

void cx64PrologueHook::hook_set_hook()
{
	if(_hook_is_set == true)
		throw std::runtime_error("Error: hook is already set");

	if(_trampoline_is_set == false)
		throw std::runtime_error("Error: trampoline not set");

	uint8_t* start_pointer = (uint8_t*)_hook_location - 0x5;

	if (memcmp((void*)start_pointer, (void*)"\xcc\xcc\xcc\xcc\xcc\xcc", 0x5) != 0)
		throw std::runtime_error("Error: unsupported function prologue");

	std::vector<uint8_t> hook_code;

	uint64_t to_location = _code_cave_location;
	uint64_t from_location = (uint64_t)start_pointer;

	uint32_t jump_displacement = to_location - from_location - 0x5;

	hook_code.push_back(0xe9);
	hook_code.insert(hook_code.end(), (uint8_t*)&jump_displacement, (uint8_t*)&jump_displacement + sizeof(jump_displacement));
	hook_code.push_back(0xeb);
	hook_code.push_back(0xf9);

	for (int i = 0; i < _displaced_instruction.size() - 2; i++)
		hook_code.push_back(0x90);

	DWORD Dummy = 0, Dummy2 = 0;

	VirtualProtect((void*)from_location, hook_code.size(), 0x40, &Dummy);

	memcpy((void*)from_location, hook_code.data(), hook_code.size());

	VirtualProtect((void*)from_location, hook_code.size(), Dummy, &Dummy2);

	_hook_is_set = true;
}

void cx64PrologueHook::hook_set_all(uint64_t hook_location, uint64_t code_cave, uint64_t hook_destination, bool call_type)
{
	if(_hook_is_set == true || _trampoline_is_set == true)
		throw std::runtime_error("Error: hook already set");

	_hook_location = hook_location;
	_code_cave_location = code_cave;
	_hook_destination = hook_destination;
	_hook_is_call_type = call_type;

	if (_hook_is_code_cave_valid() == false)
		throw std::runtime_error("Error: code cave is not sufficient");

	_hook_set_hook();
}

void cx64PrologueHook::hook_unset()
{
	DWORD Dummy = 0, Dummy2 = 0;

	VirtualProtect((void*)_hook_location, _displaced_instruction.size(), 0x40, &Dummy);

	memcpy((void*)_hook_location, _displaced_instruction.data(), _displaced_instruction.size());

	VirtualProtect((void*)_hook_location, _displaced_instruction.size(), Dummy, &Dummy2);

	_hook_location = NULL;
	_code_cave_location = NULL;
	_hook_destination = NULL;
	_displaced_instruction.clear();

	_hook_is_set = false;
	_trampoline_is_set = false;
}

uint64_t cx64PrologueHook::hook_get_trampoline_end()
{
	return _hook_trampoline_end;
}

bool cx64PrologueHook::is_hook_set()
{
	return _hook_is_set;
}

cCodeCave::cCodeCave(uint64_t abase_address, uint64_t alength)
	: base_address(abase_address), current_address(abase_address), length(alength)
{
}

std::shared_ptr<cCodeCave> cHookManager::_allocate_code_cave_in_range(uint64_t hook_location)
{
	SYSTEM_INFO SI = {};
	
	GetSystemInfo(&SI);

	bool allocation_success = false;

	uint64_t code_cave_location = hook_location + SI.dwPageSize;
	uint64_t code_cave_length = SI.dwPageSize * 8;

	while (allocation_success == false)
	{
		uint64_t real_cave_location = (uint64_t)VirtualAlloc((void*)code_cave_location, code_cave_length, MEM_COMMIT | MEM_RESERVE, 0x40);

		if (real_cave_location != 0)
		{
			code_cave_location = real_cave_location;
			break;
		}

		code_cave_location += SI.dwPageSize;
	}

	auto allocated_cave = std::make_shared<cCodeCave>(code_cave_location, code_cave_length);

	_code_cave_locations[code_cave_location] = allocated_cave;

	return allocated_cave;
}

std::shared_ptr<cCodeCave> cHookManager::_get_cave_in_range(uint64_t hook_location)
{
	for (auto& cave : _code_cave_locations)
	{
		if (qword_abs(cave.second->base_address, hook_location) > 0xffffffff)
			continue;

		if (qword_abs(cave.second->base_address + cave.second->length, cave.second->current_address) <= 0xf0)
			continue;

		return cave.second;
	}

	return nullptr;
}

std::shared_ptr<cx64PrologueHook> cHookManager::set_hook_all(uint64_t hook_location, uint64_t hook_destination, bool call_type = true)
{
	auto code_cave = _get_cave_in_range(hook_location);

	if (code_cave == nullptr)
		code_cave = _allocate_code_cave_in_range(hook_location);

	auto hook = std::make_shared<cx64PrologueHook>(_copy_patterns);
	
	hook->hook_set_all(hook_location, code_cave->current_address, hook_destination, call_type);

	code_cave->current_address += 0xf0;

	_hooks.push_back(hook);

	return hook;
}

std::shared_ptr<cx64PrologueHook> cHookManager::set_hook_trampoline(uint64_t hook_location, uint64_t hook_destination, bool call_type)
{
	auto code_cave = _get_cave_in_range(hook_location);

	if (code_cave == nullptr)
		code_cave = _allocate_code_cave_in_range(hook_location);

	auto hook = std::make_shared<cx64PrologueHook>(_copy_patterns);

	hook->hook_set_trampoline(hook_location, code_cave->current_address, hook_destination, call_type);

	code_cave->current_address += 0xf0;

	_hooks.push_back(hook);

	return hook;
}

cHookManager::cHookManager(std::shared_ptr<CopyPatterns> patterns)
	: _copy_patterns(patterns)
{
}

cHookManager::~cHookManager()
{
	for (auto hook : _hooks)
		if (hook->is_hook_set() == true)
			hook->hook_unset();
}

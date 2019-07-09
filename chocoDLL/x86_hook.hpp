#pragma once

#include <vector>
#include <string>
#include <memory>
#include <map>
#include <vector>
#include <stdexcept>

typedef std::map<std::vector<uint8_t>, uint32_t> CopyPatterns;

class cx86PrologueHook
{
private:
	uint32_t			_hook_location;
	uint32_t			_code_cave_location;
	uint32_t			_hook_destination;
	uint32_t			_hook_trampoline_end;
	bool				_hook_is_set;
	bool				_trampoline_is_set;

	std::vector<uint8_t>	_displaced_instruction;

	std::shared_ptr<CopyPatterns>	_copy_patterns;

	bool				_hook_is_call_type;

	bool				_hook_is_code_cave_valid();
	void				_hook_set_trampoline();
	void				_hook_set_hook();

public:
	cx86PrologueHook(std::shared_ptr<CopyPatterns> patterns);
	~cx86PrologueHook();

	void				hook_set_trampoline(uint32_t hook_location, uint32_t code_cave, uint32_t hook_destination, bool call_type);
	void				hook_set_hook();
	void				hook_set_all(uint32_t hook_location, uint32_t code_cave, uint32_t hook_destination, bool call_type);
	void				hook_unset();
	uint32_t			hook_get_trampoline_end();

	bool				is_hook_set();
};

class cx86CodeCave
{
private:

public:
	cx86CodeCave(uint32_t abase_address, uint32_t alength);

	uint32_t base_address;
	uint32_t current_address;
	uint32_t length;
};

class cx86HookManager
{
private:
	std::map<uint64_t, std::shared_ptr<cx86CodeCave>>	_code_cave_locations;
	std::vector<std::shared_ptr<cx86PrologueHook>>		_hooks;

	std::shared_ptr<CopyPatterns>	_copy_patterns;

	std::shared_ptr<cx86CodeCave>		_allocate_code_cave_in_range(uint32_t hook_location);
	std::shared_ptr<cx86CodeCave>		_get_cave_in_range(uint32_t hook_location);

public:
	cx86HookManager(std::shared_ptr<CopyPatterns> patterns);
	~cx86HookManager();

	std::shared_ptr<cx86PrologueHook> set_hook_all(uint32_t hook_location, uint32_t hook_destination, bool call_type);
	std::shared_ptr<cx86PrologueHook> set_hook_trampoline(uint32_t hook_location, uint32_t hook_destination, bool call_type);
};
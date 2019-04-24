#pragma once

#include <vector>
#include <string>
#include <memory>
#include <map>

typedef std::map<std::vector<uint8_t>, uint32_t> CopyPatterns;

class cx64PrologueHook
{
private:
	uint64_t			_hook_location;
	uint64_t			_code_cave_location;
	uint64_t			_hook_destination;
	uint64_t			_hook_trampoline_end;
	bool				_trampoline_is_set;
	bool				_hook_is_set;

	std::vector<uint8_t>	_displaced_instruction;

	std::shared_ptr<CopyPatterns>	_copy_patterns;

	bool				_hook_is_call_type;

	bool				_hook_is_code_cave_valid();
	void				_hook_set_trampoline();
	void				_hook_set_hook();

public:
	cx64PrologueHook(std::shared_ptr<CopyPatterns> patterns);
	~cx64PrologueHook();

	void				hook_set_trampoline(uint64_t hook_location, uint64_t code_cave, uint64_t hook_destination, bool call_type);
	void				hook_set_hook();
	void				hook_set_all(uint64_t hook_location, uint64_t code_cave, uint64_t hook_destination, bool call_type);
	void				hook_unset();
	uint64_t			hook_get_trampoline_end();

	bool				is_hook_set();
};

class cCodeCave
{
private:

public:
	cCodeCave(uint64_t abase_address, uint64_t alength);

	uint64_t base_address;
	uint64_t current_address;
	uint64_t length;
};

class cHookManager
{
private:
	std::map<uint64_t, std::shared_ptr<cCodeCave>>	_code_cave_locations;
	std::vector<std::shared_ptr<cx64PrologueHook>>		_hooks;

	std::shared_ptr<CopyPatterns>	_copy_patterns;

	std::shared_ptr<cCodeCave>		_allocate_code_cave_in_range(uint64_t hook_location);
	std::shared_ptr<cCodeCave>		_get_cave_in_range(uint64_t hook_location);

public:
	cHookManager(std::shared_ptr<CopyPatterns> patterns);
	~cHookManager();

	std::shared_ptr<cx64PrologueHook> set_hook_all(uint64_t hook_location, uint64_t hook_destination, bool call_type);
	std::shared_ptr<cx64PrologueHook> set_hook_trampoline(uint64_t hook_location, uint64_t hook_destination, bool call_type);
};
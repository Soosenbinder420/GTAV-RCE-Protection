#include <windows.h>
#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <functional>
#include <basetsd.h>
#include <mutex>

#pragma region scanner
class ptr_manage {
public:
	ptr_manage(void* hand = 0);
	ptr_manage(std::uintptr_t hand = 0);

	template <typename T>
	inline std::enable_if_t<std::is_pointer<T>::value, T> as() {
		return static_cast<T>(m_ptr);
	}

	template <typename T>
	inline std::enable_if_t<std::is_lvalue_reference<T>::value, T> as() {
		return *static_cast<std::add_pointer_t<std::remove_reference_t<T>>>(m_ptr);
	}

	template <typename T>
	inline std::enable_if_t<std::is_same<T, std::uintptr_t>::value, T> as() {
		return reinterpret_cast<T>(m_ptr);
	}

	ptr_manage add(int offset);

	inline operator bool() { return m_ptr != nullptr; }
private:
	void* m_ptr;
};

class sModule {
public:
	sModule(HMODULE hMod);
	sModule(std::string name);

	ptr_manage get_begin();
	ptr_manage get_end();
	ptr_manage get_export(std::string proc_name);

private:
	ptr_manage m_begin;
	ptr_manage m_end;
	size_t m_size{};
	std::string m_name{};
};

class find_pattern {
public:
	struct Element {
		std::uint8_t m_data{};
		bool m_wildcard{};
		Element(uint8_t data, bool wildcard) : m_data(data), m_wildcard(wildcard) { }
	};
	find_pattern(const char* pattern);
	ptr_manage scan(sModule region = sModule(nullptr));

private:
	const char* m_pat;
	std::vector<Element> m_elements;
};

struct pattern_hisnt {
	std::string m_name;
	find_pattern m_pattern;
	std::function<void(ptr_manage)> m_callback;

	pattern_hisnt(std::string name, find_pattern pattern, std::function<void(ptr_manage)> callback);
};

class pattern_batch {
public:
	void add(std::string name, find_pattern pattern, std::function<void(ptr_manage)> callback);
	void run();
private:
	std::vector<pattern_hisnt> pattern_list;
};

ptr_manage::ptr_manage(void* hand) {
	m_ptr = hand;
}
ptr_manage::ptr_manage(std::uintptr_t hand) {
	m_ptr = reinterpret_cast<void*>(hand);
}

ptr_manage ptr_manage::add(int offset) {
	return ptr_manage(as<std::uintptr_t>() + offset);
}

sModule::sModule(HMODULE hMod) : m_begin(hMod), m_end(nullptr), m_size(0) {
	auto dosHeader = ptr_manage(m_begin).as<IMAGE_DOS_HEADER*>();
	auto ntHeader = ptr_manage(m_begin).add(dosHeader->e_lfanew).as<IMAGE_NT_HEADERS*>();
	m_size = ntHeader->OptionalHeader.SizeOfImage;
	m_end = ptr_manage(m_begin.add(m_size));
}

sModule::sModule(std::string name) : sModule(GetModuleHandleA(name.c_str())) { }

ptr_manage sModule::get_begin() {
	return m_begin;
}

ptr_manage sModule::get_end() {
	return m_end;
}

ptr_manage sModule::get_export(std::string proc_name) {
	return ptr_manage(GetProcAddress(m_begin.as<HMODULE>(), proc_name.c_str()));
}

find_pattern::find_pattern(const char* pattern) {
	auto toUpper = [](char c) -> char {
		return c >= 'a' && c <= 'z' ? static_cast<char>(c + ('A' - 'a')) : static_cast<char>(c);
	};
	auto isHex = [&](char c) -> bool {
		switch (toUpper(c)) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
			return true;
		default:
			return false;
		}
	};
	do {
		if (*pattern == ' ')
			continue;
		if (*pattern == '?') {
			Element e = Element({}, true);
			m_elements.push_back(e);
			continue;
		}
		if (*(pattern + 1) && isHex(*pattern) && isHex(*(pattern + 1))) {
			char str[3] = { *pattern, *(pattern + 1), '\0' };
			auto data = std::strtol(str, nullptr, 16);

			Element e = Element(static_cast<std::uint8_t>(data), false);
			m_elements.push_back(e);
		}
	} while (*(pattern++));
}

ptr_manage find_pattern::scan(sModule region) {
	auto compareMemory = [](std::uint8_t* data, Element* elem, std::size_t num) -> bool {
		for (std::size_t i = 0; i < num; ++i) {
			if (!elem[i].m_wildcard)
				if (data[i] != elem[i].m_data)
					return false;
		}
		return true;
	};
	for (std::uintptr_t i = region.get_begin().as<std::uintptr_t>(), end = region.get_end().as<std::uintptr_t>(); i != end; ++i) {
		if (compareMemory(reinterpret_cast<std::uint8_t*>(i), m_elements.data(), m_elements.size()))
			return ptr_manage(i);
	}
	return nullptr;
}

pattern_hisnt::pattern_hisnt(std::string name, find_pattern pattern, std::function<void(ptr_manage)> callback) : m_name(std::move(name)), m_pattern(std::move(pattern)), m_callback(std::move(callback)) { }

void pattern_batch::add(std::string name, find_pattern pattern, std::function<void(ptr_manage)> callback) {
	pattern_list.emplace_back(name, pattern, callback);
}

void pattern_batch::run() {
	const sModule module = { GetModuleHandle(nullptr) };
	for (auto& hisnt : pattern_list) {
		if (auto result = hisnt.m_pattern.scan(module)) {
			if (!hisnt.m_callback)
				continue;
			if (!result.as<uintptr_t>())
				continue;
			std::invoke(std::move(hisnt.m_callback), result);
			if (!std::strcmp(hisnt.m_name.c_str(), ""))
				continue;
		}
	}
	pattern_list.clear();
}

bool init_console() {
	if (!AllocConsole())
		return false;
	const HANDLE console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
	const HWND console_window = GetConsoleWindow();
	if (!console_handle || !console_window)
		return false;
	freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
	SetConsoleTitleW(L"Anti-RCE");
	SetConsoleCP(CP_UTF8);
	SetConsoleOutputCP(CP_UTF8);
	RECT lp_rect{};
	GetWindowRect(console_window, &lp_rect);
	MoveWindow(console_window, lp_rect.left, lp_rect.top, 900, 500, TRUE);
	CONSOLE_SCREEN_BUFFER_INFOEX csbiInfo{};
	csbiInfo.cbSize = sizeof(csbiInfo);
	GetConsoleScreenBufferInfoEx(console_handle, &csbiInfo);
	csbiInfo.ColorTable[1] = RGB(229, 137, 226);
	SetConsoleScreenBufferInfoEx(console_handle, &csbiInfo);
	SetConsoleTextAttribute(console_handle, 1);
	SetLayeredWindowAttributes(console_window, NULL, 245, LWA_ALPHA);
	return true;
}
#pragma endregion

uint8_t* handle_sge;
uint8_t* gpn;

bool hk_handle_sge(int64_t a1, int64_t a2, int64_t a3)
{
	switch (*reinterpret_cast<int*>(a1 + 0x224)) {
	case 1279059857:
	case -343495611:
		std::cout << "Blocked RCE from " << (reinterpret_cast<const char*(*)(int)>(gpn))(*reinterpret_cast<char*>(a2 + 0x21)) << std::endl;
		return true;
	}
	*handle_sge = 0x40;
	bool ret = (reinterpret_cast<decltype(&hk_handle_sge)>(handle_sge))(a1, a2, a3);
	*handle_sge = 0xCC;
	return ret;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) CreateThread(0, 0, [](LPVOID) -> DWORD {
		init_console();
		pattern_batch sussy;
		sussy.add("ligma", "40 53 48 81 EC ? ? ? ? 44 8B 81", [=](ptr_manage ptr) {
			handle_sge = ptr.as<uint8_t*>();
		});
		sussy.add("fuck", "40 53 48 83 EC 20 80 3D ? ? ? ? ? 8B D9 74 22 33 D2 E8", [=](ptr_manage ptr) {
			gpn = ptr.as<uint8_t*>();
		});
		sussy.run();
		*handle_sge = 0xCC;
		AddVectoredExceptionHandler(1, [](EXCEPTION_POINTERS* exp) -> LONG {
			if (exp->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;
			if (reinterpret_cast<PVOID>(exp->ContextRecord->Rip) != handle_sge) return EXCEPTION_CONTINUE_SEARCH;
			exp->ContextRecord->Rip = reinterpret_cast<DWORD64>(hk_handle_sge);
			return EXCEPTION_CONTINUE_EXECUTION;
		});
		return 0;
    }, 0, 0, 0);
    return TRUE;
}
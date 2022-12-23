# Proof-of-concept without any obfuscation

This is the very first proof-of-concept that we made: a shellcode loader that is not obfuscated at all.  
Multiple executables are made from one source file: for each shellcode file that must be built with the file (defined in the `CMakeLists.txt` file), two executables are made: an easily debuggable one, which is printing useful information and making breaks waiting for a user input to keep going, so that a debugger can attach to it easily, and a basic one, that prints nothing, and that is not especially made to be easily debuggable.  

The steps the program follows are the followings:
- It allocates a memory area than the same size as the shellcode
- It copies the shellcode to this allocated memory area
- It creates a thread whose start address is the allocated memory area, so that it executes the shellcode

If everything goes well, the shellcode should be executed.  
Keep in mind that even though some of the shellcodes are benign (the calc one for example, spawn a calculator), others are also purposely malicious (TCP reverse shells).  
Therefore, we advise you to test the executables in a virtual machine, and to disable windows defender in order to be able to run them.

# Shellcodes

In this folder, you'll find all the shellcodes we use in our proof-of-concepts.  
If you want to add a shellcode, create a new `.hpp` file, and put your shellcode as an `unsigned char[]`, called `shellcode` (the name is important, the source programs may not work if you name it something else).  
Furthermore, if you wish to use the Python encrypter script (located in src/technique_1_encrypting_shellcode), place a line break between the `=` declaration of the shellcode variable and the shellcode itself. The shellcode needs to be a string (may be on multiple lines) with each byte at its hex format. See the shellcode files for examples of a valid shellcode file.

# Second evasion technique: reducing the executable's entropy

There is two way we will try to reduce entropy.
We can either add an high level image entropy in the code.
The second option is add some words of the english dictionnary.

The paper we study recommand to encrypt our shellcode with one of these method. 

We will do the second option and encrypt our shellcode using random words from dictionnary.

The python script will do the encryption and will output 2 c++ array : the key and the encrypted shellcode

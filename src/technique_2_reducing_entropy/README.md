# Second evasion technique: reducing the executable's entropy

There is two way we will try to reduce entropy.
We can either add an high level image entropy in the code.
The second option is add some words of the english dictionnary.

The paper we study recommand to encrypt our shellcode with one of these method. 
My idea will be to SHA either the image or the words then takes the x first bits to encrypt the shellcode.

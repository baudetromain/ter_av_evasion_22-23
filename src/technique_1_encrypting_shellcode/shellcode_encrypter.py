import sys
import re


def main():

    if len(sys.argv) != 4:
        usage()
        
    shellcode_filename = sys.argv[1]
    output_filename = sys.argv[2]
    xor_key = sys.argv[3]
    
    shellcode_bytes, shellcode_variable_name = parse_shellcode(shellcode_filename)

    if len(xor_key) > len(shellcode_bytes):
        print("Warning: the key is longer than the shellcode. Only a part of it will be used.")
    elif len(xor_key) < len(shellcode_bytes):
        print("Warning: the key is shorter than the shellcode. The shellcode will be encrypted by repeating the key, but it is advised to prompt a key that is as long as the shellcode.")

    xor_key_bytes = key_to_bytes_array(xor_key)
    xored_shellcode_bytes = xor(shellcode_bytes, xor_key_bytes)
    write_shellcode_to_file(xored_shellcode_bytes, output_filename, shellcode_variable_name)
    
    
def parse_shellcode(filename):
    file_lines = get_file_lines(filename)
    shellcode_variable_name = get_shellcode_variable_name(file_lines)
    shellcode_string = filter_shellcode(file_lines)
    shellcode_bytes = string_to_bytes(shellcode_string)
    return shellcode_bytes, shellcode_variable_name
    
    
def get_file_lines(filename):
        file = open(filename, "r")
        lines = []
        for line in file:
            lines.append(line)
        file.close()
        return lines


def get_shellcode_variable_name(lines):
    regex = re.compile("^.*unsigned char (.+)\\[\\] =.*$")
    for line in lines:
        match = regex.match(line)
        if match:
            return match.group(1)
        
        
def filter_shellcode(lines):
    regex = re.compile("^\s*\"(.*)\";?$")
    temp = list(filter(lambda line: regex.match(line), lines))
    temp = list(map(lambda line: regex.match(line).group(1), temp))
    return "".join(list(map(lambda line: line.replace("\\x", ""), temp)))
    

def string_to_bytes(string):
    bytes_array = []
    for i in range(0, len(string), 2):
        bytes_array.append(int(string[i:i+2], 16))
    return bytes_array


def key_to_bytes_array(key):
    return [ord(c) for c in key]


def xor(shellcode_bytes, key_bytes):
    xored_shellcode_bytes = []
    for i in range(len(shellcode_bytes)):
        xored_shellcode_bytes.append(shellcode_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return xored_shellcode_bytes


def write_shellcode_to_file(shellcode_bytes, filename, shellcode_variable_name):
    line_length = 15
    content = ""
    content += (f"unsigned char xored_{shellcode_variable_name}[] =\n")
    bytes_chunks = [shellcode_bytes[x:x+line_length] for x in range(0, len(shellcode_bytes), line_length)]
    for bytes_chunk in bytes_chunks:
        content += bytes_to_shellcode(bytes_chunk)
    content = content[:-1] 
    content += ";\n"

    file = open(filename, "w")
    file.write(content)
    file.close()


def bytes_to_shellcode(bytes):
    shellcode = "".join(list(map(lambda byte: my_hex(byte), bytes)))
    return "\t\t\"" + shellcode + "\"\n"


def my_hex(byte):
    hexed_byte = hex(byte)
    if len(hexed_byte) == 4:
        return "\\" + hexed_byte[1:]
    else:
        return "\\x0" + hexed_byte[-1]


def usage():
    print(f"Usage: {sys.argv[0]} <shellcode> <output file> <key>")
    exit(0)
    
    
main()

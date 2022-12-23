import re
import argparse


def main():
    parser = argparse.ArgumentParser(prog="Shellcode encrypter",
                                     description="Encrypts shellcode by xoring it with a key")

    parser.add_argument("input_file",
                        help="Input file containing the shellcode")
    parser.add_argument("-o", "--output-file",
                        dest="output_file",
                        help="Output file to write the encrypted shellcode to (default is encrypted_shellcode.hpp)",
                        default="encrypted_shellcode.hpp",
                        required=False)
    parser.add_argument("--shellcode-variable-name",
                        dest="shellcode_variable_name",
                        help="Name of the variable containing the encrypted shellcode in the output file (default is "
                             "shellcode)",
                        default="shellcode",
                        required=False)
    parser.add_argument("--output-key",
                        dest="output_key",
                        help="Use this option to write the key inside a variable in the output file, instead of "
                             "printing it to the console",
                        action="store_true",
                        required=False)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-k", "--key",
                       dest="key",
                       help="Key to use for encryption (use --random-key to generate a random key)",
                       required=False)
    group.add_argument("--random-key",
                       dest="random_key",
                       help="Use this option to generate a random key (of the same length as the shellcode)",
                       action="store_true",
                       required=False)

    args = parser.parse_args()

    shellcode_bytes = parse_shellcode(args.input_file)
    if args.random_key:
        key = generate_random_key(len(shellcode_bytes))
    else:
        key = key_to_bytes_array(args.key)

    if len(key) > len(shellcode_bytes):
        print("Warning: the key is longer than the shellcode. Only a part of it will be used.")
    elif len(key) < len(shellcode_bytes):
        print("Warning: the key is shorter than the shellcode. The shellcode will be encrypted by repeating the key, "
              "but it is advised to prompt a key that is as long as the shellcode.")

    xored_shellcode_bytes = xor(shellcode_bytes, key)
    write_shellcode_to_file(xored_shellcode_bytes,
                            args.output_file,
                            args.shellcode_variable_name,
                            key=None if args.output_key else key)
    print(f"Shellcode encrypted and written to {args.output_file}")
    if args.output_key:
        print(f"Key: {bytes_to_shellcode(key)}")


def parse_shellcode(filename):
    file_lines = get_file_lines(filename)
    shellcode_string = filter_shellcode(file_lines)
    shellcode_bytes = string_to_bytes(shellcode_string)
    return shellcode_bytes


def get_file_lines(filename):
    file = open(filename, "r")
    lines = []
    for line in file:
        lines.append(line)
    file.close()
    return lines


def filter_shellcode(lines):
    regex = re.compile("^\s*\"(.*)\";?$")
    temp = list(filter(lambda line: regex.match(line), lines))
    temp = list(map(lambda line: regex.match(line).group(1), temp))
    return "".join(list(map(lambda line: line.replace("\\x", ""), temp)))


def string_to_bytes(string):
    bytes_array = []
    for i in range(0, len(string), 2):
        bytes_array.append(int(string[i:i + 2], 16))
    return bytes_array


def key_to_bytes_array(key):
    return [ord(c) for c in key]


def xor(shellcode_bytes, key_bytes):
    xored_shellcode_bytes = []
    for i in range(len(shellcode_bytes)):
        xored_shellcode_bytes.append(shellcode_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return xored_shellcode_bytes


def write_shellcode_to_file(shellcode_bytes, filename, shellcode_variable_name, key=None):
    line_length = 15
    content = ""
    if key:
        bytes_chunks = [key[i:i + line_length] for i in range(0, len(key), line_length)]
        content += "unsigned char key[] = \n"
        for bytes_chunk in bytes_chunks:
            content += f"\t\t{bytes_to_shellcode(bytes_chunk)}"
        content = content[:-1] + ";\n\n"
    content += f"unsigned char {shellcode_variable_name}[] =\n"
    bytes_chunks = [shellcode_bytes[x:x + line_length] for x in range(0, len(shellcode_bytes), line_length)]
    for bytes_chunk in bytes_chunks:
        content += f"\t\t{bytes_to_shellcode(bytes_chunk)}"
    content = content[:-1] + ";\n"

    file = open(filename, "w")
    file.write(content)
    file.close()


def bytes_to_shellcode(byte_array):
    shellcode = "".join(list(map(lambda byte: my_hex(byte), byte_array)))
    return "\"" + shellcode + "\"\n"


def my_hex(byte):
    hexed_byte = hex(byte)
    if len(hexed_byte) == 4:
        return "\\" + hexed_byte[1:]
    else:
        return "\\x0" + hexed_byte[-1]


def generate_random_key(length):
    import random
    return [random.randint(0, 255) for _ in range(length)]


main()

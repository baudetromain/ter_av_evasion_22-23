# This program is made to encode a shellcode as a list of english words
# First, it must generate a bijection between each possible byte (256
# possible valutes) and 256 english words. This bijection can simpy be
# represented as a list of 256 words, where the index of the word is the
# byte value.
# Then, it must read the shellcode, and for each byte, count the following
# occurences of the same byte, and add the corresponding english word in
# a list, and the number of occurences in another list.
# Without this optimization, the shellcode would be too long.

import argparse
import re
import random_words


def main():

    # parse the arguments
    args = parse_args()

    # parse the shellcode
    occurences, bytes = (list[int], list[int]) = parse_shellcode(args.input_file)

    # The bijection
    bijection: list[str] = list(filter(lambda word: len(word) == 5, random_words.RandomWords().random_words(count=4655, min_letter_count=5)))[:256]

    # open the output file
    with open(args.output_file, 'w') as output_file:

        # write the key (the bijection)
        write_key(output_file, bijection)

        # write the occurences
        write_occurences(output_file, occurences)

        # write the bytes
        write_bytes(output_file, bytes, bijection)


# This function parses the program's arguments
def parse_args():
    parser = argparse.ArgumentParser(description='Encode a shellcode as a list of english words')

    # add an input_file argument
    parser.add_argument('-i', '--input-file',
                        required=True,
                        help='The path of the input file')

    # add an output_file argument (optionnal, default is "natural_language_shellcode.hpp")
    parser.add_argument('-o', '--output-file',
                        default='natural_language_shellcode.hpp',
                        help='The path of the output file')

    # parse the arguments
    args = parser.parse_args()

    return args


# This function reads the shellcode from the input file, and returns it as a couple of list,
# where the first list contains the number of occurences of each byte, and the second
# list contains the bytes themselves
def parse_shellcode(input_file_path: str) -> (list[int], list[int]):
    # the list of occurences
    occurences: list[int] = []

    # the list of bytes
    bytes: list[int] = []

    # the current count of occurences of the current byte
    current_occurences: int = 0

    # the current byte
    current_byte: int | None = None

    # open the input file
    with open(input_file_path, 'r') as input_file:

        # read the file's lines
        lines: list[str] = input_file.readlines()

        # the shellcode lines' regex
        shellcode_lines_regex = re.compile('^\s*\"(.*)\";?$')

        # iterate through the lines
        for line in lines:

            # if a line matches the shellcode lines' regex, then we pass it to the parse_shellcode_line function
            if shellcode_lines_regex.match(line):

                # get the list of bytes
                shellcode_bytes: list[int] = parse_shellcode_line(line)

                # iterate through the bytes
                for byte in shellcode_bytes:

                    # if byte is the same as the current byte, then we increment the current count of occurences
                    if byte == current_byte:
                        current_occurences += 1

                    # if byte is different from the current byte, then we add the current count of occurences and
                    # the current byte to the list
                    else:

                        # if current_byte is None, then it's the first byte, so we don't add it to the lists
                        if current_byte is not None:
                            occurences.append(current_occurences)
                            bytes.append(current_byte)

                        current_byte = byte
                        current_occurences = 1

        # add the last byte to the lists
        occurences.append(current_occurences)
        bytes.append(current_byte)

        return occurences, bytes


# This function takes a line as its parameter, and returns the shellcode as a list of bytes
# There's no need to check if the line is a shellcode line, because this function is only called
# if the line matches the shellcode lines' regex
def parse_shellcode_line(line: str) -> list[int]:
    # the regex that matches a byte
    byte_regex = re.compile('\\\\x([0-9a-f]{2})')

    # the list of bytes
    bytes: list[int] = []

    # iterate through the bytes
    for byte in byte_regex.findall(line):
        # convert the byte from hexadecimal to decimal
        bytes.append(int(byte, 16))

    return bytes


# This function writes the key (the bijection) to the output file
# since the key is a list of string of 5 characters long each (plus the null byte), the variable
# will be the following: unsigned char[256][6] key = { "word1", "word2", ... };
def write_key(output_file, bijection: list[str]):

    # write the variable declaration
    output_file.write('unsigned char key[256][6] = {\n')

    # creates a list called words_chunk, that will contain 10 words at a time
    words_chunk: list[list[str]] = [bijection[x:x+10] for x in range(0, len(bijection), 10)]

    # iterate through the words_chunk list
    for words in words_chunk:

        # write a \t
        output_file.write('\t')

        # iterate through the words
        for word in words:

            # write the word
            output_file.write(f'"{word}", ')

        # write a \n
        output_file.write('\n')

    # write the closing bracket
    output_file.write('};\n\n')


# This function writes the occurences to the output file
# since the occurences is a list of integers, the variable will be the following:
# unsigned int occurences[<len>] = { occurences[0], occurences[1], occurences[2], ... };
def write_occurences(output_file, occurences: list[int]):

    # write the variable declaration
    output_file.write(f'unsigned int occurences[{len(occurences)}] = {{\n')

    # create a list called occurences_chunk, that will contain 30 occurences at a time
    occurences_chunk: list[list[int]] = [occurences[x:x+30] for x in range(0, len(occurences), 30)]

    # iterate through the occurences_chunk list
    for occurences in occurences_chunk:

        # write a \t
        output_file.write('\t')

        # iterate through the occurences
        for occurence in occurences:

            # write the occurence
            output_file.write(f'{occurence}, ')

        # write a \n
        output_file.write('\n')

    # write the closing bracket
    output_file.write('};\n\n')


# This function writes the bytes to the output file
#
def write_bytes(output_file, bytes, bijection):



if __name__ == '__main__':
    main()

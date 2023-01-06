import argparse
import random


def main():
    parser = argparse.ArgumentParser()

    # add a functions-names argument, that can take multiple argument, and is required
    parser.add_argument("-f", "--functions-names",
                        nargs="+",
                        required=True,
                        help="The names of the functions to obfuscate")

    # add an output-file argument, that can take only one argument, and has a default value of
    # "obfuscated_functions.hpp"
    parser.add_argument("-o", "--output-file",
                        default="obfuscated_functions.hpp",
                        help="The name of the output file")

    # parse the arguments
    args = parser.parse_args()

    # get the functions names
    functions_names: list[str] = args.functions_names
    # get the output file name
    output_file_name: str = args.output_file

    # call the function to generate the obfuscated functions names
    obfuscated_functions_names: list[(list[int], list[int])] = generate_obfuscated_functions_names(functions_names)

    # call the function to generate the c declaration of the variables as a string
    c_declarations: str = generate_c_declaration(obfuscated_functions_names, functions_names)

    # write the c declaration in the output file
    with open(output_file_name, "w") as output_file:
        output_file.write(c_declarations)

    # print the result of the execution in the console
    print(f"Successfully generated the obfuscated functions names in {output_file_name}")


def generate_obfuscated_functions_names(functions_names: list[str]) -> list[(list[int], list[int])]:
    """
    This function takes a list of functions names as its parameter, and returns a list of pairs Each pair contains
    the XOR key at first position (as an array of number between 0 and 255), and the obfuscated (XORed) function name
    at second position *
    :param functions_names: a list of strings containing the functions names
    :return: a list of pairs, each pair contains the XOR key at first position (as an array of number between 0 and
    255), and the obfuscated (XORed) function name at second position
    """

    # create the empty list that we'll fill
    obfuscated_functions_names: list[(list[int], list[int])] = []

    # for each function name
    for function_name in functions_names:
        # generate a single random byte to append at the end of the key AND the obfuscated function name, to be the
        # null-byte that indicates teh end of the string
        null_byte: int = random.randint(0, 255)

        # generate a random key
        key: list[int] = [random.randint(0, 255) for _ in range(len(function_name))]
        key.append(null_byte)

        # obfuscate the function name
        obfuscated_function_name: list[int] = [ord(function_name[i]) ^ key[i] for i in range(len(function_name))]
        obfuscated_function_name.append(null_byte)

        # add the pair to the list
        obfuscated_functions_names.append((key, obfuscated_function_name))

    return obfuscated_functions_names


def generate_c_declaration(obfuscated_functions_names: list[(list[int], list[int])],
                           original_function_names: list[str]) -> str:
    """
    This function takes a list of obfuscated functions names as its parameter, and returns a string containing the
    C declarations of the variables, i.e. for each couple, an "unsigned char key[]" and an
    "unsigned char function_name[]"
    :param obfuscated_functions_names: a list of pairs, each pair contains the XOR key at first position (as an array of
    number between 0 and 255), and the obfuscated (XORed) function name at second position
    :param original_function_names: a list of strings containing the original function names
    :return: a string containing the C declarations of the variables, i.e. for each couple, an "unsigned char key[]" and
    an "unsigned char function_name[]"
    """

    # the first task that we have to do is to look for illegal characters in the function names, and replace them with a
    # "_". The reason we do that is that this program may also be used to obfuscate dll files' names, and these ones
    # contains a "." character, which is not allowed in C variable names
    for i in range(len(original_function_names)):
        original_function_names[i] = original_function_names[i].replace(".", "_")

    # create the empty string that we'll fill
    c_declaration: str = ""

    # for each pair
    for i, (key, obfuscated_function_name) in enumerate(obfuscated_functions_names):
        # add the declaration of the key
        # add the type of the key
        # the key's type is "unsigned char", and the variable's name is "<original function name>_key[]"
        c_declaration += "unsigned char " + original_function_names[i] + "_key[] = "

        # call the function to get the c-formatted array of the key, and add the final ";"
        c_declaration += f"{get_c_formatted_array(key)};\n"

        # add the declaration of the obfuscated function name
        # add the type of the obfuscated function name
        # the obfuscated function name's type is "unsigned char", and the variable's name is
        # "<original function name>_obfuscated_function_name[]"
        c_declaration += "unsigned char " + original_function_names[i] + "_obfuscated_function_name[] = "

        # call the function to get the c-formatted array of the obfuscated function name, and add the final ";"
        c_declaration += f"{get_c_formatted_array(obfuscated_function_name)};\n"

        # add a new line to clearly separate the declarations
        c_declaration += "\n"

    return c_declaration


def get_c_formatted_array(obfuscated_function_name: list[int]) -> str:
    """
    This function takes a list of integers as its parameter, and returns a string containing the C-formatted array of
    the integers, i.e. "u{0x1f, 0x2c, 0x3a}"
    :param obfuscated_function_name: a list of integers, each one being one byte of the obfuscated function name
    :return: a string containing the C-formatted array of the integers, i.e. "{0x1f, 0x2c, 0x3a}"
    """

    # create a string with only the "{" character
    c_formatted_array: str = "{"

    # iterate through the bytes and write each one in the string as a hexadecimal number, preceeding it with a space and
    # appending a comma to it
    for byte in obfuscated_function_name:
        c_formatted_array += f" 0x{byte:02x},"

    # remove the last comma and add the final "}"
    c_formatted_array = c_formatted_array[:-1] + " }"

    return c_formatted_array


if __name__ == "__main__":
    main()

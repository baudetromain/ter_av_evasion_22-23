cmake_minimum_required(VERSION 3.23.2)

project(av_evasion_ter_22-23 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Set the source file
set(SOURCE_FILE src/no_obfuscation/shellcode_dropper.cpp)

# Set the static linking flags
set(CMAKE_EXE_LINKER_FLAGS "-static")

# Set the list of shellcodes
set(SHELLCODES
        src/shellcodes/unobfuscated_calc.hpp
        src/shellcodes/unobfuscated_unstaged_meterpreter_reverse_shell.hpp
        src/shellcodes/unobfuscated_staged_meterpreter_reverse_shell.hpp
        )

# Loop over the list of shellcodes
foreach(SHELLCODE ${SHELLCODES})
    # Extract the shellcode name from the file path
    get_filename_component(SHELLCODE_NAME ${SHELLCODE} NAME_WE)
    # ancient config used regex, but somehow it didn't work
    # string(REGEX REPLACE ".*/([^/]*).hpp" "\\1" SHELLCODE_NAME ${SHELLCODE})

    # Create an executable for the current shellcode
    add_executable(${SHELLCODE_NAME} ${SOURCE_FILE})
    # Create another executable called the same but starting with "debug_"
    add_executable(debug_${SHELLCODE_NAME} ${SOURCE_FILE})

    # Add the current shellcode as a preprocessor definition for the executable, called SHELLCODE_PATH, but add the absolute path to the file
    target_compile_definitions(${SHELLCODE_NAME} PRIVATE SHELLCODE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/${SHELLCODE}" PRIVATE DEBUG=0)
    # Set the debug preprocessor definitions as above, but with debug=1
    target_compile_definitions(debug_${SHELLCODE_NAME} PRIVATE SHELLCODE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/${SHELLCODE}" PRIVATE DEBUG=1)

    # Set the static linking flags for both executables
    set_target_properties(${SHELLCODE_NAME} PROPERTIES LINK_FLAGS "-static")
    set_target_properties(debug_${SHELLCODE_NAME} PROPERTIES LINK_FLAGS "-static")

    # old line where the relative path was set by hand
    # target_compile_definitions(${SHELLCODE_NAME} PRIVATE SHELLCODE_PATH="../../${SHELLCODE}")
endforeach()

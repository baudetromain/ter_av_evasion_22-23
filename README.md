# Antivirus evasion techniques Research project

School research project about antivirus evasion techniques used by malwares in 2022.  
The goal of the project is to study obfuscation and evasion techniques, make a proof-of-concept of each of them, and finally combine every single one of them into a shellcode loader that is not detected as a malware by Windows defender for endpoints.


# The code

We are implementing the obfuscation and evasion techniques one by one.  
We dedicate a subdirectory of the `src` directory to each technique.  
All the different shellcodes are defined in header files that are in the `src/shellcode` directory.

# Requirements

You'll need the [cmake](https://cmake.org/) build tool in version 3.23.2 or higher.
As a compiler, it is advised that you use [minGW](https://www.mingw-w64.org/), for example the one bundled by default in the [CLion IDE](https://www.jetbrains.com/clion/). We've ran into issues when compiling our executables with MSVC.  
There's also one (there may be more in the future) script written in python that we use to encrypt shellcodes, so you need [Python](https://www.python.org/) 3.8 or higher in order to use it.

# Building the executables

The CMakeLists.txt file at the root directory defines the way the project must be compile.  
To create the cmake build files,issue the following commands in a console in the project's root directory:
```powershell
mkdir cmake-build
cd cmake-build
cmake ..
```
To build the executables, go in the created `cmake-build` directory and issue this command:
```powershell
cmake --build .
```

# Team members

**BAUDET Romain**  
**MARSAIS-LACOSTE Marcel**  
**TURLETTI Théo**  

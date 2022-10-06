# PT_NOTE->PT_LOAD Injector

This is entirely meant to be a learning exercise. The odds that the code sucks is extremely high. 

## Why?

This project is intended to teach about parsing ELF files, and, ultimately, be an automated way to inject ELF binaries with the PT_NOTE->PT_LOAD injection trick.

## What?
The ELF parsing is pretty self explanatory, but the PT_LOAD trick works like so:
1. Find a PT_NOTE program header in an ELF binary that is writeable
2. Change the PT_NOTE to a PT_LOAD and change the value to an address where you have stored shell code
3. The address in the previous step will usually be the end of the file (we will append some shell code to the binary and point to it)

## TODO
- [ ] Figure out how to dynamically set Program Header array instead of hard code it
- [ ] Fix code to add infection
- [ ] Include ability to work on PIE executables

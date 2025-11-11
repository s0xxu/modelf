When running use ./modelf program
I recommend writing your own shellcode, and using xxd -i code for a formatted version.

This program writes code to .fini section and redirects e_entry to start of our code, also enchances the size of the segment.
Uses section/segment headers to analyze the data and find a suitable "code cave". I found out that if you write to .init or .plt, your program will simply not load and the interpreter will throw your errors.
I was originally trying to bypass ASLR, but I couldn't figure out a way how to, that's why there's some unused entry points. Just returning to the original e_entry will cause a segfault, as the base is not included, so I like to write a execve call into the binary, as it will replace the entire process.
There is no "complex error handling" on the shellcode, so once you've gotten your shell or whatever you like it will simply just hang/exit, and you can throw it a signal to exit.


This is my virustotal scan, which I'm quite happy with, there will be some "unusual" behavior noted in relations/behavior.
https://www.virustotal.com/gui/file/9e005bc2c1f06c612b6aa62c357c96c53a3fb65cd2bcbeb27fee64bfa61a8918/detection
I'd like to note that this ran perfectly on 6.17.4-arch2-1 and 6.14.0-35-generic with the basic configurations, and no root.


Building this taught me elf headers, and gave me an insight into how the compiler uses data from the sections to load our program into memory at runtime.
For educational purposes

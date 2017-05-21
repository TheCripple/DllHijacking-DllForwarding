# DllHijacking

Taken from the MSF project.

Compile with:

cl /Fe:[outfile].dll /LD msf_template_nothread.c

or mingw:

i686-w64-mingw32-gcc hijack.c -o hijack.dll -shared [-lws2_32] [strip]

# DllForwarding

Use the dllexportdump.py script to create .def file.

python dllexportdump.py user32.dll

Then compile hijack.dll in combination with the .def file:

i686-w64-mingw32-gcc hijack.c -o hijack.dll -shared strip forward.def

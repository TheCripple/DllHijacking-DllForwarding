# DllHijacking

Taken from the MSF project.

Compile with:

cl /Fe:[outfile].dll /LD msf_template_nothread.c

or mingw:

i686-w64-mingw32-gcc hijack.c -o hijack.dll -shared -s [-lws2_32] 

# DllForwarding

Use the dllexportdump.py script to create .def file.

python dllexportdump.py user32.dll user32_real.dll > forward.def

Then compile hijack.dll in combination with the .def file:

i686-w64-mingw32-gcc msf_template_nothread.c -o forward_hijack.dll -shared -s forward.def

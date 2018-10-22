#!/usr/bin/python
#Created by Vivek Ramachandran from pentester academy

import sys, pefile

dllName = sys.argv[1]

newDllName = sys.argv[2].replace(".dll", "")

pe = pefile.PE(dllName)

if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') :
	print "No Export table! Is this a DLL??"
	sys.exit(-1)

# Lets create a DEF file for gcc/ld (mingw)

print "LIBRARY \"" + dllName.replace(".dll","") + "\""
print "EXPORTS\n"


for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
	
	if exp.name :
                        print "%s=%s.%s @%d" % (exp.name, newDllName, exp.name, exp.ordinal)
	else :
                        print "ord%d=%s.ord%d @%d NONAME" %(exp.ordinal, newDllName, exp.ordinal, exp.ordinal)

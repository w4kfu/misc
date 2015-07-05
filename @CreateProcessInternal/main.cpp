#include <stdio.h>
#include <Windows.h>

#define FILENAME L"messagebox.exe"

/* ntdef.h */

#if !defined NTSTATUS
    typedef LONG NTSTATUS;
#endif
typedef LONG KPRIORITY;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation,
} PROCESSINFOCLASS;

typedef enum _SECTION_INFORMATION_CLASS {
    SectionBasicInformation,
    SectionImageInformation,
    MaxSectionInfoClass  // MaxSectionInfoClass should always be the last enum
} SECTION_INFORMATION_CLASS;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

#if _WIN64
typedef struct _SECTION_IMAGE_INFORMATION {
    ULONGLONG TransferAddress;
    ULONG ZeroBits;
    ULONGLONG MaximumStackSize;
    ULONGLONG CommittedStackSize;
    ULONG SubSystemType;
    union {
        struct {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        }u;
        ULONG SubSystemVersion;
    };
    ULONG GpValue;
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    BOOLEAN Spare1;
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG Reserved[ 1 ];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;
#else
typedef struct _SECTION_IMAGE_INFORMATION {
    PVOID TransferAddress;
    ULONG ZeroBits;
    SIZE_T MaximumStackSize;
    SIZE_T CommittedStackSize;
    ULONG SubSystemType;
    union {
        struct {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        }u;
        ULONG SubSystemVersion;
    };
    ULONG GpValue;
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    BOOLEAN Spare1;
    ULONG LoaderFlags;
    ULONG Reserved[ 2 ];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;
#endif

typedef struct _INITIAL_TEB {
    struct {
        PVOID OldStackBase;
        PVOID OldStackLimit;
    } OldInitialTeb;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackAllocationBase;
} INITIAL_TEB, *PINITIAL_TEB;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

//
// Low order 2 bits of handle value used as flag bits.
//

#define RTL_USER_PROC_CURDIR_CLOSE      0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT    0x00000003

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG  ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;        // ProcessParameters
    UNICODE_STRING DllPath;         // ProcessParameters
    UNICODE_STRING ImagePathName;   // ProcessParameters
    UNICODE_STRING CommandLine;     // ProcessParameters
    PVOID Environment;              // NtAllocateVirtualMemory

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;     // ProcessParameters
    UNICODE_STRING DesktopInfo;     // ProcessParameters
    UNICODE_STRING ShellInfo;       // ProcessParameters
    UNICODE_STRING RuntimeData;     // ProcessParameters
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[ RTL_MAX_DRIVE_LETTERS ];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

/* OBJECT_ATTRIBUTES */
#if _WIN64
    typedef struct _OBJECT_ATTRIBUTES {
        ULONG Length;
        ULONG64 RootDirectory;
        ULONG64 ObjectName;
        ULONG Attributes;
        ULONG64 SecurityDescriptor;
        ULONG64 SecurityQualityOfService;
    } OBJECT_ATTRIBUTES;
    typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
    typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;
#else
    typedef struct _OBJECT_ATTRIBUTES {
        ULONG Length;
        ULONG RootDirectory;
        ULONG ObjectName;
        ULONG Attributes;
        ULONG SecurityDescriptor;
        ULONG SecurityQualityOfService;
    } OBJECT_ATTRIBUTES;
    typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
    typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;
#endif

#if _WIN64
#define MakeZwSyscall(type, var, ...)                       \
    typedef NTSTATUS (__fastcall *type) (__VA_ARGS__);      \
    type var = NULL;
#else
#define MakeZwSyscall(type, var, ...)                       \
    typedef NTSTATUS (__stdcall *type) (__VA_ARGS__);       \
    type var = NULL;
#endif

/* ZwCreateProcess */
MakeZwSyscall(ZwCreateProcess_lpfn, ZwCreateProcess,
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle OPTIONAL,
    HANDLE DebugPort OPTIONAL,
    HANDLE ExceptionPort OPTIONAL)

/* ZwQuerySection */
MakeZwSyscall(ZwQuerySection_lpfn, ZwQuerySection,
    HANDLE 	SectionHandle,
    SECTION_INFORMATION_CLASS SectionInformationClass,
    PVOID SectionInformation,
    SIZE_T Length,
    PSIZE_T ResultLength)

/* ZwCreateThread */
MakeZwSyscall(ZwCreateThread_lpfn, ZwCreateThread,
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ProcessHandle,
        PCLIENT_ID ClientId,
        PCONTEXT ThreadContext,
        PINITIAL_TEB InitialTeb,
        BOOLEAN CreateSuspended)

/* ZwCreateSection */
MakeZwSyscall(ZwCreateSection_lpfn, ZwCreateSection,
    PHANDLE  SectionHandle,
    ACCESS_MASK  DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
    PLARGE_INTEGER  MaximumSize OPTIONAL,
    ULONG  SectionPageProtection,
    ULONG  AllocationAttributes,
    HANDLE  FileHandle OPTIONAL)

/* ZwAllocateVirtualMemory */
MakeZwSyscall(ZwAllocateVirtualMemory_lpfn, ZwAllocateVirtualMemory,
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        ULONG ZeroBits,
        PULONG AllocationSize,
        ULONG AllocateType,
        ULONG Protect)

/* ZwQueryInformationProcess */
MakeZwSyscall(ZwQueryInformationProcess_lpfn, ZwQueryInformationProcess,
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength)

/* RtlInitUnicodeString */
MakeZwSyscall(RtlInitUnicodeString_lpfn, RtlInitUnicodeString,
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString)

/* RtlCreateProcessParameters */
MakeZwSyscall(RtlCreateProcessParameters_lpfn, RtlCreateProcessParameters,
    PRTL_USER_PROCESS_PARAMETERS *ProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData)

/* ZwWriteVirtualMemory */
MakeZwSyscall(ZwWriteVirtualMemory_lpfn, ZwWriteVirtualMemory,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    VOID *Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten)

/* RtlDestroyProcessParameters */
MakeZwSyscall(RtlDestroyProcessParameters_lpfn, RtlDestroyProcessParameters,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters)

/* ZwProtectVirtualMemory */
MakeZwSyscall(ZwProtectVirtualMemory_lpfn, ZwProtectVirtualMemory,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect)

#if _WIN64
void BaseInitializeContext(CONTEXT *Context, DWORD64 Rbx, DWORD64 Rax, DWORD64 Rsp, DWORD64 Rip)
{
    Context->SegGs = 0x00;
    Context->Rax = Rax;
    Context->Rbx = Rbx;
    Context->SegEs = 0x2b;
    Context->SegDs = 0x2b;
    Context->SegSs = 0x2b;
    Context->SegFs = 0x53;
    Context->SegGs = 0x2b;
    Context->SegCs = 0x33;
    Context->EFlags = 0x3000;
    Context->Rip = Rip;
    Context->Rsp = Rsp;
    Context->ContextFlags = 0x10007;
}
#else
void BaseInitializeContext(CONTEXT *Context, DWORD Ebx, DWORD Eax, DWORD Esp, DWORD Eip)
{
    Context->SegGs = 0x00;
    Context->Eax = Eax;
    Context->Ebx = Ebx;
    Context->SegEs = 0x20;
    Context->SegDs = 0x20;
    Context->SegSs = 0x20;
    Context->SegFs = 0x38;
    Context->SegCs = 0x18;
    Context->EFlags = 0x3000;
    Context->Eip = Eip;
    Context->Esp = Esp;
    Context->ContextFlags = 0x10007;
}
#endif

BOOL ResolveZwFunc(VOID)
{
    ZwCreateProcess = (ZwCreateProcess_lpfn)GetProcAddress(GetModuleHandleA("ntdll"), "ZwCreateProcess");
    if (ZwCreateProcess == NULL) {
        fprintf(stderr, "[-] GetProcAddress failed : %lu\n", GetLastError());
        return FALSE;
    }
    ZwQuerySection = (ZwQuerySection_lpfn)GetProcAddress(GetModuleHandleA("ntdll"), "ZwQuerySection");
    if (ZwQuerySection == NULL) {
        fprintf(stderr, "[-] GetProcAddress failed : %lu\n", GetLastError());
        return FALSE;
    }
    ZwCreateSection = (ZwCreateSection_lpfn)GetProcAddress(GetModuleHandleA("ntdll"), "ZwCreateSection");
    if (ZwCreateSection == NULL) {
        fprintf(stderr, "[-] GetProcAddress failed : %lu\n", GetLastError());
        return FALSE;
    }
    ZwWriteVirtualMemory = (ZwWriteVirtualMemory_lpfn)GetProcAddress(GetModuleHandleA("ntdll"), "ZwWriteVirtualMemory");
    if (ZwWriteVirtualMemory == NULL) {
        fprintf(stderr, "[-] GetProcAddress(..., \"ZwWriteVirtualMemory\") failed : %lu\n", GetLastError());
        return FALSE;
    }
    RtlDestroyProcessParameters = (RtlDestroyProcessParameters_lpfn)GetProcAddress(GetModuleHandleA("ntdll"), "RtlDestroyProcessParameters");
    if (RtlDestroyProcessParameters == NULL) {
        fprintf(stderr, "[-] GetProcAddress(..., \"RtlDestroyProcessParameters\") failed : %lu\n", GetLastError());
        return FALSE;
    }
    ZwQueryInformationProcess = (ZwQueryInformationProcess_lpfn)GetProcAddress(GetModuleHandleA("ntdll"), "ZwQueryInformationProcess");
    if (ZwQueryInformationProcess == NULL) {
        fprintf(stderr, "[-] GetProcAddress(..., \"ZwQueryInformationProcess\") failed : %lu\n", GetLastError());
        return FALSE;
    }
    RtlInitUnicodeString = (RtlInitUnicodeString_lpfn)GetProcAddress(GetModuleHandleA("ntdll"), "RtlInitUnicodeString");
    if (RtlInitUnicodeString == NULL) {
        fprintf(stderr, "[-] GetProcAddress(..., \"RtlInitUnicodeString\") failed : %lu\n", GetLastError());
        return FALSE;
    }
    RtlCreateProcessParameters = (RtlCreateProcessParameters_lpfn)GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateProcessParameters");
    if (RtlCreateProcessParameters == NULL) {
        fprintf(stderr, "[-] GetProcAddress(..., \"RtlCreateProcessParameters\") failed : %lu\n", GetLastError());
        return FALSE;
    }
    ZwAllocateVirtualMemory = (ZwAllocateVirtualMemory_lpfn)GetProcAddress(GetModuleHandleA("ntdll"), "ZwAllocateVirtualMemory");
    if (ZwAllocateVirtualMemory == NULL) {
        fprintf(stderr, "[-] GetProcAddress(..., \"ZwAllocateVirtualMemory\") failed : %lu\n", GetLastError());
        return FALSE;
    }
    ZwProtectVirtualMemory = (ZwProtectVirtualMemory_lpfn)GetProcAddress(GetModuleHandleA("ntdll"), "ZwProtectVirtualMemory");
    if (ZwProtectVirtualMemory == NULL) {
        fprintf(stderr, "[-] GetProcAddress(..., \"ZwProtectVirtualMemory\") failed : %lu\n", GetLastError());
        return FALSE;
    }
    ZwCreateThread = (ZwCreateThread_lpfn)GetProcAddress(GetModuleHandleA("ntdll"), "ZwCreateThread");
    if (ZwCreateThread == NULL) {
        fprintf(stderr, "[-] GetProcAddress(..., \"ZwCreateThread\") failed : %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

PWSTR CopyEnvironment(HANDLE hProcess)
{
	PWSTR env = GetEnvironmentStringsW();
    SIZE_T AllocationSize;
    PVOID BaseAddress = 0;
    NTSTATUS Status;

	for (AllocationSize = 0; env[AllocationSize] != 0; AllocationSize += wcslen(env + AllocationSize) + 1);
    AllocationSize *= sizeof (*env);
	Status = ZwAllocateVirtualMemory(hProcess, &BaseAddress, 0,
							(PULONG)&AllocationSize, MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "CopyEnvironment - ZwAllocateVirtualMemory failed : 0x%08X\n", Status);
		return NULL;
	}
	Status = ZwWriteVirtualMemory(hProcess, BaseAddress, env, AllocationSize, 0);
	if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "CopyEnvironment - ZwWriteVirtualMemory failed : 0x%08X\n", Status);
		return NULL;
	}
	return (PWSTR)BaseAddress;
}

BOOL BaseCreateStack(HANDLE hSection, HANDLE hProcess, PINITIAL_TEB InitTeb, PCONTEXT Context)
{
    NTSTATUS Status;
    SECTION_IMAGE_INFORMATION ImageInfo;
    ULONG AllocationSize;
    ULONG OldProtect;
    PVOID BaseAddress;

    Status = ZwQuerySection(hSection, SectionImageInformation, &ImageInfo, sizeof(ImageInfo), NULL);
    if (!NT_SUCCESS(Status)) {
		fprintf(stderr, "main - ZwQuerySection failed : 0x%08X\n", Status);
		return FALSE;
   	}
    printf("[+] ImageInfo.MaximumStackSize   : 0x%08X\n", ImageInfo.MaximumStackSize);
    printf("[+] ImageInfo.CommittedStackSize : 0x%08X\n", ImageInfo.CommittedStackSize);
#if _WIN64
    printf("[+] ImageInfo.TransferAddress    : 0x%016llX\n", ImageInfo.TransferAddress);
#else
    printf("[+] ImageInfo.TransferAddress    : 0x%08X\n", ImageInfo.TransferAddress);
#endif
	Status = ZwAllocateVirtualMemory(hProcess, &InitTeb->StackAllocationBase,
                                    0, (PULONG)&ImageInfo.MaximumStackSize, MEM_RESERVE,
                                    PAGE_READWRITE);
	if (!NT_SUCCESS(Status)) {
		fprintf(stderr, "BaseCreateStack - ZwAllocateVirtualMemory failed : 0x%08X\n", Status);
		return FALSE;
	}
    printf("[+] InitTeb->StackAllocationBase  : 0x%08X\n", InitTeb->StackAllocationBase);
	InitTeb->StackBase = (PVOID)((DWORD64)InitTeb->StackAllocationBase + ImageInfo.MaximumStackSize);
	InitTeb->StackLimit = (PVOID)((DWORD64)InitTeb->StackBase - ImageInfo.CommittedStackSize);
	AllocationSize = (ULONG)(ImageInfo.CommittedStackSize + 0x1000);
	BaseAddress = (PVOID)((PCHAR)InitTeb->StackBase - AllocationSize);
	Status = ZwAllocateVirtualMemory(hProcess, (PVOID*)&BaseAddress, 0, &AllocationSize,
								MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(Status)) {
		fprintf(stderr, "BaseCreateStack - ZwAllocateVirtualMemory failed : 0x%08X\n", Status);
		return FALSE;
	}
	AllocationSize = 0x1000;
	Status = ZwProtectVirtualMemory(hProcess, (PVOID*)&BaseAddress, (PSIZE_T)&AllocationSize,
								PAGE_READWRITE|PAGE_GUARD, &OldProtect);
	if (!NT_SUCCESS(Status)) {
		fprintf(stderr, "BaseCreateStack - ZwProtectVirtualMemory failed : 0x%08X\n", Status);
		return FALSE;
	}
#if _WIN64
    BaseInitializeContext(Context, 0x00, 0x00, (DWORD64)InitTeb->StackBase - 4, (DWORD64)ImageInfo.TransferAddress);
#else
    BaseInitializeContext(Context, 0x00, 0x00, (DWORD)InitTeb->StackBase - 4, (DWORD)ImageInfo.TransferAddress);
#endif
    return TRUE;
}

BOOL BasePushProcessParameters(HANDLE hProcess)
{
    NTSTATUS Status;
    ULONG AllocationSize;
    PVOID BaseAddress;
    PROCESS_BASIC_INFORMATION ProcessInfo;
    UNICODE_STRING FilePath;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    wchar_t CurrentDir[0x200];
    wchar_t PathFile[0x200];

    if (!GetCurrentDirectoryW(sizeof (CurrentDir) - 1, CurrentDir)) {
		fprintf(stderr, "GetCurrentDirectory failed : 0x%lu\n", GetLastError());
		return FALSE;
    }
    swprintf_s(PathFile, sizeof (PathFile), L"%s%s", CurrentDir, FILENAME);
    Status = ZwQueryInformationProcess(hProcess, ProcessBasicInformation,
								&ProcessInfo, sizeof(ProcessInfo), NULL);
    if (!NT_SUCCESS(Status)) {
		fprintf(stderr, "ZwQueryInformationProcess failed : 0x%08X\n", Status);
		return FALSE;
   	}
#if _WIN64
    printf("[+] ProcessInfo.PebBaseAddress  : 0x%016llX\n", ProcessInfo.PebBaseAddress);
#else
    printf("[+] ProcessInfo.PebBaseAddress  : 0x%08X\n", ProcessInfo.PebBaseAddress);
#endif
    RtlInitUnicodeString(&FilePath, (PWSTR)PathFile);
    printf("[+] path = %S\n", PathFile);
	Status = RtlCreateProcessParameters(&ProcessParameters, &FilePath, 0, 0, 0, 0, 0, 0, 0, 0);
	if (!NT_SUCCESS(Status)) {
		fprintf(stderr, "RtlCreateProcessParameters failed : 0x%08X\n", Status);
		return FALSE;
	}
	ProcessParameters->Environment = CopyEnvironment(hProcess);
	AllocationSize = ProcessParameters->MaximumLength;
	BaseAddress = 0;
	Status = ZwAllocateVirtualMemory(hProcess, &BaseAddress, 0, &AllocationSize, MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(Status)) {
		fprintf(stderr, "Main - ZwAllocateVirtualMemory failed : 0x%08X\n", Status);
		return FALSE;
	}
#if _WIN64
    printf("[+] ProcessInfo.PebBaseAddress  : 0x%016llX\n", BaseAddress);
#else
    printf("[+] ProcessInfo.PebBaseAddress  : 0x%08X\n", BaseAddress);
#endif
	Status = ZwWriteVirtualMemory(hProcess, BaseAddress, ProcessParameters, ProcessParameters->MaximumLength, 0);
	if (!NT_SUCCESS(Status)) {
		fprintf(stderr, "Main - ZwWriteVirtualMemory failed : 0x%08X\n", Status);
		return FALSE;
	}
#if _WIN64
/*
0:001> dt nt!_PEB ProcessParameters
ntdll!_PEB
   +0x020 ProcessParameters : Ptr64 _RTL_USER_PROCESS_PARAMETERS
*/
	Status = ZwWriteVirtualMemory(hProcess, (PCHAR)(ProcessInfo.PebBaseAddress) + 0x020, &BaseAddress, sizeof(BaseAddress), 0);
#else
	Status = ZwWriteVirtualMemory(hProcess, (PCHAR)(ProcessInfo.PebBaseAddress) + 0x10, &BaseAddress, sizeof(BaseAddress), 0);
#endif
	if (!NT_SUCCESS(Status)) {
		fprintf(stderr, "ZwWriteVirtualMemory failed : 0x%08X\n", Status);
		return FALSE;
	}
	Status = RtlDestroyProcessParameters(ProcessParameters);
	if (!NT_SUCCESS(Status)) {
		fprintf(stderr, "RtlDestroyProcessParameters failed : 0x%08X\n", Status);
		return FALSE;
	}
    return TRUE;
}

int main(void)
{
    NTSTATUS Status;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hSection = INVALID_HANDLE_VALUE;
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    HANDLE hThread = INVALID_HANDLE_VALUE;
    OBJECT_ATTRIBUTES ObjectAttributes;
    INITIAL_TEB InitTeb;
    CONTEXT Context;
    CLIENT_ID ClientId;

    RtlZeroMemory(&InitTeb, sizeof (InitTeb));
    RtlZeroMemory(&Context, sizeof (Context));
    RtlZeroMemory(&ClientId, sizeof (ClientId));
    if (ResolveZwFunc() == FALSE) {
        return -1;
    }

    /* Open the image file (*.exe) to be executed inside the process */
    hFile = CreateFileW(FILENAME, GENERIC_READ | FILE_EXECUTE | SYNCHRONIZE, FILE_SHARE_READ,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] CreateFileA failed : %lu\n", GetLastError());
        goto end;
    }
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	Status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &ObjectAttributes,
                            0, PAGE_EXECUTE, SEC_IMAGE, hFile);
	if (!NT_SUCCESS(Status)) {
		fprintf(stderr, "main - ZwCreateSection failed : 0x%08X\n", Status);
		goto end;
	}
    printf("[+] hSection : 0x%08X\n", hSection);

    /* Create the Windows executive object */
    Status = ZwCreateProcess(&hProcess, PROCESS_ALL_ACCESS, NULL,
                            GetCurrentProcess(), TRUE, hSection, NULL, NULL);
	if (!NT_SUCCESS(Status)) {
		fprintf(stderr, "main - ZwCreateProcess failed : 0x%08X\n", Status);
		goto end;
	}
    printf("[+] hProcess : 0x%08X\n", hProcess);

    /* Create the initial thread (stack, context, ...) */
    if (BaseCreateStack(hSection, hProcess, &InitTeb, &Context) == FALSE) {
        goto end;
    }

    /* Creates and initializes a thread object (suspended)*/
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	Status = ZwCreateThread(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
						&ClientId, &Context, &InitTeb, TRUE);
	if (!NT_SUCCESS(Status)) {
		fprintf(stderr, "ZwCreateThread failed : 0x%08X\n", Status);
		goto end;
	}

    /* Init ProcessParameters in PEB */
    if (BasePushProcessParameters(hProcess) == FALSE) {
        goto end;
    }
    ResumeThread(hThread);
end:
    CloseHandle(hProcess);
    CloseHandle(hSection);
    CloseHandle(hFile);
    return 0;
}

///* CsrClientCallServer */
//#if _WIN64
//    typedef NTSTATUS (__fastcall *CsrClientCallServer_lpfn) (PVOID Message,
//        PVOID CaptureBuffer,
//        ULONG Opcode,
//        ULONG Length);
//#else
//    typedef NTSTATUS (__stdcall *CsrClientCallServer_lpfn) (PVOID Message,
//        PVOID CaptureBuffer,
//        ULONG Opcode,
//        ULONG Length);
//#endif
//CsrClientCallServer = (CsrClientCallServer_lpfn)GetProcAddress(GetModuleHandleA("ntdll"), "CsrClientCallServer");
//if (CsrClientCallServer == NULL) {
//    fprintf(stderr, "[-] GetProcAddress failed : %lu\n", GetLastError());
//    goto end;
//}
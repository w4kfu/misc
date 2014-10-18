#include <stdio.h>
#include <windows.h>

// cl MarkFileUnsafe.cpp Ole32.lib

// Interface IZoneIdentifier
// RIID CD45F185-1B21-48E2-967B-EAD743A8914E

/*struct IZoneIdentifier {
void *QueryInterface;
void *AddRef;
void *Release;
void *GetId;
void *SetId;
void *Remove;
};*/

// Interface IPersistFile
// RIID 0000010B-0000-0000-C000-000000000046

/*struct IPersistFile {
void *QueryInterface;
void *AddRef;
void *Release;
void *GetClassID;
void *IsDirty;
void *Load;
void *Save;
void *SaveCompleted;
void *GetCurFile;
};*/

void MarkFileUnsafe(WCHAR *wFileName)
{
    HRESULT    hr;
	IZoneIdentifier *pizone = NULL;
	IPersistFile *piper = NULL;

    hr = CoInitializeEx( NULL, COINIT_APARTMENTTHREADED );
    if (FAILED(hr))
    {
        printf("[-] Failed CoInitializeEx - pEnroll [%x]\n", hr);
        goto error;
    }
    hr = CoCreateInstance(CLSID_PersistentZoneIdentifier,
                           NULL,
                           CLSCTX_INPROC_SERVER,
                           IID_IZoneIdentifier,
                           (void **)&pizone);
    if (FAILED(hr))
    {
        printf("[-] Failed CoCreateInstance - pEnroll [%x]\n", hr);
        goto error;
    }
	if (pizone->SetId(URLZONE_INTERNET) != S_OK)
	{
        printf("[-] SetId failed\n");
        goto error;	
	}
	hr = pizone->QueryInterface(IID_IPersistFile, (void**)&piper);
    if (FAILED(hr))
    {
        printf("[-] QueryInterface failed\n");
        goto error;
    }
	hr = piper->Save(wFileName, TRUE);
    if (FAILED(hr))
    {
        printf("[-] Failed Save\n");
        goto error;
    }
error:
    if (pizone != NULL)
        pizone->Release();
    if (piper != NULL)
        piper->Release();
	CoUninitialize();
}

void test(WCHAR *wFileName)
{
	WCHAR lpFileName[MAX_PATH];
	WCHAR lpString[MAX_PATH];

	swprintf_s(lpFileName, MAX_PATH - 1, L"%s:Zone.Identifier", wFileName);
	swprintf_s(lpString, MAX_PATH - 1, L"%d", URLZONE_INTERNET);
	WritePrivateProfileStringW(L"ZoneTransfer", L"ZoneId", lpString, lpFileName);
}

int main(int argc, char *argv[])
{
	test(L"C:\\Users\\w4kfu\\Downloads\\simple.exe");
	//MarkFileUnsafe(L"C:\\Users\\w4kfu\\Downloads\\simple.exe");

	return 0;
}
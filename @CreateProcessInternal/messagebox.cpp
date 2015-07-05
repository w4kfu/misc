#include <Windows.h>

#pragma comment(lib, "user32.lib")
#pragma comment(linker,"/SUBSYSTEM:WINDOWS")

int CALLBACK WinMain(
  _In_ HINSTANCE hInstance,
  _In_ HINSTANCE hPrevInstance,
  _In_ LPSTR     lpCmdLine,
  _In_ int       nCmdShow
)
{
    (void)hInstance;
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;

    MessageBoxA(NULL, "TEST", "TEST", 0);
    return 0;
}
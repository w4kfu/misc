option casemap :none

IFDEF RAX

extrn ExitProcess: PROC
extrn MessageBoxA: PROC

ELSE

.486
.model flat, stdcall

ExitProcess PROTO STDCALL :DWORD
MessageBoxA PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD

ENDIF

.data

caption db 'caption', 0 
text    db 'moo', 0


.code 

start PROC 

    IFDEF RAX
    
    sub     rsp, 28h
    xor     r9, r9
    lea     r8, caption
    lea     rdx, text
    xor     rcx, rcx
    
    ELSE
    
    push    0h
    push    offset caption
    push    offset text
    push    0h
    
    ENDIF
    call    MessageBoxA
    xor     eax, eax
    call    ExitProcess


start ENDP 
End
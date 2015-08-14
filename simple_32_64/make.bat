@SET OBJNAME=simple.obj

@WHERE ml64
@IF %ERRORLEVEL% NEQ 0 (@SET MLBIN=ml & @SET NOUT=simple_32.exe) ELSE (@SET MLBIN=ml64 & @SET NOUT=simple_64.exe)

@if exist OBJNAME del OBJNAME
@if exist NOUT del NOUT

@%MLBIN% simple.asm /c
@if errorlevel 1 goto errml

@link simple.obj kernel32.lib user32.lib /FIXED /subsystem:windows /entry:start /OUT:%NOUT%
@if errorlevel 1 goto errlink

:errml
:errlink
@if exist %OBJNAME% del %OBJNAME%
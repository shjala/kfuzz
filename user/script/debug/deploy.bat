<!-- : --- Self-Elevating Batch Script ---------------------------
@whoami /groups | find "S-1-16-12288" > nul && goto :admin
set "ELEVATE_CMDLINE=cd /d "%~dp0" & call "%~f0" %*"
cscript //nologo "%~f0?.wsf" //job:Elevate & exit /b

-->
<job id="Elevate"><script language="VBScript">
  Set objShell = CreateObject("Shell.Application")
  Set objWshShell = WScript.CreateObject("WScript.Shell")
  Set objWshProcessEnv = objWshShell.Environment("PROCESS")
  strCommandLine = Trim(objWshProcessEnv("ELEVATE_CMDLINE"))
  objShell.ShellExecute "cmd", "/c " & strCommandLine, "", "runas"
</script></job>
:admin -----------------------------------------------------------

@echo off
echo Running as elevated user.
echo Script file : %~f0
echo Arguments   : %*
echo Working dir : %cd%
echo.

start dbgview.exe

copy /Y "x:\kflog\kflog.sys" "x:\kttest\kflog.sys"
copy /Y "x:\ktest\ktest.sys" "x:\kttest\ktest.sys"

copy /Y "x:\kflog\kflog.sys" %cd%\kflog.sys
copy /Y "x:\ktest\ktest.sys" %cd%\ktest.sys

sc stop kflog
sc delete kflog
sc create kflog binPath= %cd%\kflog.sys type= kernel
sc start kflog

sc stop ktest
sc delete ktest
sc create ktest binPath= %cd%\ktest.sys type= kernel
sc start ktest

set /p temp="Hit enter to unload drivers"

sc stop kflog
sc delete kflog

sc stop ktest
sc delete ktest

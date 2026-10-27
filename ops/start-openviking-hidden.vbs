' OpenViking windowless launcher.
' Runs start-openviking-hidden.cmd with window style 0 so neither the watchdog console
' nor the Ollama Gin access log ever appears on the desktop.
' The Scheduled Task calls: wscript.exe //B "<this file>"
Option Explicit
Dim shell, fso, base, cmd, rc
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
base = fso.GetParentFolderName(WScript.ScriptFullName)
cmd = "cmd.exe /d /c """ & base & "\start-openviking-hidden.cmd"""
rc = shell.Run(cmd, 0, True)
WScript.Quit rc

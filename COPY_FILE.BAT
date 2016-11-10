@echo off
copy .\Release\Win32\x64dbg_AttachHelper.dll C:\MyTools\x64dbg\release\x32\plugins\AttachHelper.dp32
copy .\Release\Win32\x64dbg_AttachHelper.dll .\AttachHelper.dp32
copy .\Release\x64\x64dbg_AttachHelper.dll C:\MyTools\x64dbg\release\x64\plugins\AttachHelper.dp64
copy .\Release\x64\x64dbg_AttachHelper.dll .\AttachHelper.dp64
pause
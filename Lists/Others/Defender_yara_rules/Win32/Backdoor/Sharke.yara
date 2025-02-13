rule Backdoor_Win32_Sharke_A_2147600324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sharke.A"
        threat_id = "2147600324"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\sharK 3\\Injector" wide //weight: 1
        $x_1_2 = "WriteProcessMemory" wide //weight: 1
        $x_1_3 = "SetThreadContext" wide //weight: 1
        $x_1_4 = "HTTP\\shell\\open\\command\\" wide //weight: 1
        $x_1_5 = "regread" wide //weight: 1
        $x_1_6 = {6d 4d 61 69 6e 00 00 00 6d 6f 64 55 73 65 72 6c 61 6e 64 55 6e 68 6f 6f 6b 69 6e 67}  //weight: 1, accuracy: High
        $x_1_7 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Sharke_B_2147600325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sharke.B"
        threat_id = "2147600325"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\sharK 3\\Server" wide //weight: 1
        $x_1_2 = "UnhookWindowsHookEx" wide //weight: 1
        $x_1_3 = "request_download" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "URLDownloadToFileA" wide //weight: 1
        $x_1_6 = "if exist  \"" wide //weight: 1
        $x_1_7 = "iloveshark" wide //weight: 1
        $x_1_8 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Sharke_D_2147601597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sharke.D"
        threat_id = "2147601597"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_1_2 = "\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_3 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_4 = "capCreateCaptureWindowA" ascii //weight: 1
        $x_1_5 = "CMSNMessengerPasswords" ascii //weight: 1
        $x_1_6 = "CMSNExplorerPasswords" ascii //weight: 1
        $x_1_7 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_8 = "VMWareService.exe" wide //weight: 1
        $x_1_9 = "\\Mozilla\\Firefox\\" wide //weight: 1
        $x_1_10 = "OpenProcessToken" ascii //weight: 1
        $x_1_11 = "COutlookAccounts" ascii //weight: 1
        $x_1_12 = "regsvr32 /s /u" wide //weight: 1
        $x_1_13 = "NtShutdownSystem" ascii //weight: 1
        $x_1_14 = "iamasharkplugin" ascii //weight: 1
        $x_1_15 = "VMWareUser.exe" wide //weight: 1
        $x_1_16 = "wscript.shell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (13 of ($x*))
}

rule Backdoor_Win32_Sharke_E_2147602671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sharke.E"
        threat_id = "2147602671"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.shark-project.net" wide //weight: 1
        $x_1_2 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_3 = "AllocateAndGetTcpExTableFromStack" ascii //weight: 1
        $x_1_4 = "EncryptString" ascii //weight: 1
        $x_1_5 = "wscript.shell" wide //weight: 1
        $x_1_6 = "\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_7 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_8 = "cmd.exe /c \"" wide //weight: 1
        $x_1_9 = "\\Desktop\\Shark\\Projekt" ascii //weight: 1
        $x_1_10 = "capGetDriverDescriptionA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Sharke_F_2147603406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sharke.F"
        threat_id = "2147603406"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sharK\\Server" wide //weight: 10
        $x_1_2 = "C:\\update_svr_di.exe" wide //weight: 1
        $x_1_3 = "%ACCHECK%" wide //weight: 1
        $x_1_4 = "PANIC_KILL" wide //weight: 1
        $x_1_5 = "OKOKOKOKOK" wide //weight: 1
        $x_1_6 = "\\regssvr32.bat" wide //weight: 1
        $x_1_7 = "rmdir \"" wide //weight: 1
        $x_1_8 = "iLyBk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Sharke_C_2147608397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sharke.C"
        threat_id = "2147608397"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.shark-project.net" wide //weight: 1
        $x_1_2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_1_3 = "\\sharK\\Server\\" wide //weight: 1
        $x_1_4 = "\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_5 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_6 = "*messenger.shark" wide //weight: 1
        $x_1_7 = "iamasharkplugin" wide //weight: 1
        $x_1_8 = "*pstorage.shark" wide //weight: 1
        $x_1_9 = "C:\\shark.update" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_Win32_Sharke_L_2147609151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sharke.L"
        threat_id = "2147609151"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6d 4d 61 69 6e 00 00 00 6d 6f 64 55 73 65 72 6c 61 6e 64 55 6e 68 6f 6f 6b 69 6e 67}  //weight: 10, accuracy: High
        $x_10_2 = "MSVBVM60.DLL" ascii //weight: 10
        $x_1_3 = "kernel33.dll" wide //weight: 1
        $x_1_4 = "%defaultbrowser%" wide //weight: 1
        $x_1_5 = "HTTP\\shell\\open\\command\\" wide //weight: 1
        $x_3_6 = "X:\\sharK 3\\Cli" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}


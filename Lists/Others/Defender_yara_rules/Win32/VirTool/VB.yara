rule VirTool_Win32_VB_L_2147601056_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VB.L"
        threat_id = "2147601056"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c 00 00 00 00 44 6c 6c 46 75 6e 63 74 69 6f 6e 43 61 6c 6c 00 00 00 5f 5f 76 62 61 45 78 63 65 70 74 48 61 6e 64 6c 65 72 00 00 00 00 50 72 6f 63 43 61 6c 6c 45 6e 67 69 6e 65}  //weight: 1, accuracy: High
        $x_1_2 = {57 00 6a 00 60 00 73 00 7f 00 68 00 78 00 6e 00 50 00 40 00 67 00 6c 00 62 00 7e 00 61 00 7c 00 72 00 61 00 4a 00 40 00 71 00 77 00 7e 00 74 00 6b 00 6e 00 42 00 5c 00 55 00 53 00 50 00 46 00 4a 00 51 00 70 00 42 00 5a 00 5a 00 43 00 44 00 42 00 71 00 6b 00 57 00 40 00 5d 00 5d 00 41 00 51 00 47 00 6a 00 75 00 4a 00 56 00 4d 00 48 00 59 00 4f 00 1e 00 77 00 25 00 2d 00 32 00 26 00 36 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 00 42 00 46 00 4c 00 4e 00 00 00 0a 00 00 00 25 00 45 00 46 00 4c 00 4e 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 00 42 00 53 00 56 00 41 00 00 00 0a 00 00 00 25 00 45 00 53 00 56 00 41 00}  //weight: 1, accuracy: High
        $x_1_5 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "ShellExecuteA" ascii //weight: 1
        $x_1_8 = "GetExitCodeThread" ascii //weight: 1
        $x_1_9 = {40 a6 6f 2c ad 3c c1 51 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VB_M_2147601579_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VB.M"
        threat_id = "2147601579"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Program Files\\vb6mini\\VB6.OLB" ascii //weight: 1
        $x_1_2 = {4f 70 65 6e 50 72 6f 63 65 73 73 ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "EnumProcesses" ascii //weight: 1
        $x_1_4 = "EnumProcessModules" ascii //weight: 1
        $x_1_5 = "TerminateProcess" ascii //weight: 1
        $x_1_6 = "SHGetSpecialFolderLocation" ascii //weight: 1
        $x_1_7 = "SHGetPathFromIDListA" ascii //weight: 1
        $x_1_8 = "360safe.exe" wide //weight: 1
        $x_1_9 = "kavstart.exe" wide //weight: 1
        $x_1_10 = "regedit.exe" wide //weight: 1
        $x_1_11 = "mcshield.exe" wide //weight: 1
        $x_1_12 = "ravmon.exe" wide //weight: 1
        $x_1_13 = "naprdmgr.exe" wide //weight: 1
        $x_1_14 = "trojdie.exe" wide //weight: 1
        $x_1_15 = "msconfig.exe" wide //weight: 1
        $x_1_16 = "icesword.exe" wide //weight: 1
        $x_1_17 = "killme.bat" wide //weight: 1
        $x_1_18 = "if exist" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


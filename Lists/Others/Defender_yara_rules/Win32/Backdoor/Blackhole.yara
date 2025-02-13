rule Backdoor_Win32_Blackhole_R_2147595186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blackhole.R"
        threat_id = "2147595186"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackhole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "380"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "KeySpy.dll" ascii //weight: 100
        $x_100_2 = "Keylog.txt" ascii //weight: 100
        $x_100_3 = {47 65 74 4b 65 79 00}  //weight: 100, accuracy: High
        $x_10_4 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_5 = "FPUMaskValue" ascii //weight: 10
        $x_10_6 = "StartHook" ascii //weight: 10
        $x_10_7 = "StopHook" ascii //weight: 10
        $x_5_8 = "CreateToolhelp32Snapshot" ascii //weight: 5
        $x_5_9 = "Toolhelp32ReadProcessMemory" ascii //weight: 5
        $x_5_10 = "Process32First" ascii //weight: 5
        $x_5_11 = "Process32Next" ascii //weight: 5
        $x_5_12 = "Thread32First" ascii //weight: 5
        $x_5_13 = "Thread32Next" ascii //weight: 5
        $x_5_14 = "Module32First" ascii //weight: 5
        $x_5_15 = "Module32Next" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Blackhole_S_2147595187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blackhole.S"
        threat_id = "2147595187"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackhole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "187"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "GetKey.dll" ascii //weight: 100
        $x_10_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_3 = "FPUMaskValue" ascii //weight: 10
        $x_10_4 = "StartHook" ascii //weight: 10
        $x_10_5 = "StopHook" ascii //weight: 10
        $x_5_6 = "WriteFile" ascii //weight: 5
        $x_5_7 = "UnmapViewOfFile" ascii //weight: 5
        $x_5_8 = "MapViewOfFile" ascii //weight: 5
        $x_5_9 = "FindFirstFileA" ascii //weight: 5
        $x_5_10 = "CreateFileMappingA" ascii //weight: 5
        $x_5_11 = "CreateFileA" ascii //weight: 5
        $x_5_12 = "UnhookWindowsHookEx" ascii //weight: 5
        $x_5_13 = "SetWindowsHookExA" ascii //weight: 5
        $x_5_14 = "CallNextHookEx" ascii //weight: 5
        $x_1_15 = "Unit_DllMain" ascii //weight: 1
        $x_1_16 = {47 65 74 4b 65 79 00}  //weight: 1, accuracy: High
        $x_2_17 = "_kaspersky" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_10_*) and 9 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 4 of ($x_10_*) and 9 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Blackhole_T_2147595460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blackhole.T"
        threat_id = "2147595460"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackhole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "FPUMaskValue" ascii //weight: 10
        $x_5_3 = "ShellExecuteA" ascii //weight: 5
        $x_5_4 = "OpenSCManagerA" ascii //weight: 5
        $x_5_5 = "ShowSuperHidden" ascii //weight: 5
        $x_1_6 = "OPEN=sxs.exe" ascii //weight: 1
        $x_1_7 = "shell\\open\\Command=sxs.exe" ascii //weight: 1
        $x_1_8 = "services.exe" ascii //weight: 1
        $x_1_9 = "SOFTWARE\\Classes\\.dlll" ascii //weight: 1
        $x_1_10 = "dlll_auto_file" ascii //weight: 1
        $x_1_11 = "SOFTWARE\\Classes\\dl1_auto_file\\shell\\open\\command" ascii //weight: 1
        $x_1_12 = "soundman" ascii //weight: 1
        $x_1_13 = "server.exe" ascii //weight: 1
        $x_1_14 = "WinStar.dlll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Blackhole_U_2147595468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blackhole.U"
        threat_id = "2147595468"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackhole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "138"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "BlackHole Remote Control Services" ascii //weight: 100
        $x_10_2 = "brc_Server.exe" ascii //weight: 10
        $x_10_3 = "brc_Server.dll" ascii //weight: 10
        $x_5_4 = "http://www.138soft.org" wide //weight: 5
        $x_5_5 = "lovejingtao@21cn.com" wide //weight: 5
        $x_5_6 = "http://ip.aq138.com/setip.asp" ascii //weight: 5
        $x_1_7 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_8 = "FPUMaskValue" ascii //weight: 1
        $x_1_9 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Blackhole_U_2147595468_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blackhole.U"
        threat_id = "2147595468"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackhole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "153"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "BlackHole Remote Control Services" ascii //weight: 100
        $x_10_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_3 = "FPUMaskValue" ascii //weight: 10
        $x_5_4 = "CreateToolhelp32Snapshot" ascii //weight: 5
        $x_5_5 = "Toolhelp32ReadProcessMemory" ascii //weight: 5
        $x_5_6 = "Process32First" ascii //weight: 5
        $x_5_7 = "socket" ascii //weight: 5
        $x_5_8 = "shutdown" ascii //weight: 5
        $x_5_9 = "setsockopt" ascii //weight: 5
        $x_2_10 = "http://www.138soft.org" ascii //weight: 2
        $x_2_11 = "http://www.138soft.org" wide //weight: 2
        $x_1_12 = "lovejingtao@21cn.com" ascii //weight: 1
        $x_1_13 = "getip.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 6 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 6 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Blackhole_Y_2147602372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blackhole.Y"
        threat_id = "2147602372"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackhole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 5c 00 00 00 48 54 54 50 4d 61 69 6c 20 55 73 65 72 20 4e 61 6d 65 00 00 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {66 74 70 3a 2f 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 45 3a 50 61 73 73 77 6f 72 64 2d 50 72 6f 74 65 63 74 65 64 20 53 69 74 65 73 00 65 31 36 31 32 35 35 61 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4b 2f 57 69 6e 58 50 2f 57 69 6e 32 30 30 33 20 4c 6f 67 69 6e 20 3e 3e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 73 65 72 44 6f 6d 61 69 6e 20 20 3a 00}  //weight: 1, accuracy: Low
        $x_1_4 = {53 65 6e 64 50 73 77 5f 4b 65 79 6c 6f 67 5f 53 79 73 49 6e 66 6f 54 68 72 65 61 64 55 8b ec}  //weight: 1, accuracy: High
        $x_1_5 = {42 6c 61 63 6b [0-1] 48 6f 6c 65 32 30 30}  //weight: 1, accuracy: Low
        $x_1_6 = "ExPloReR.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Blackhole_Z_2147605515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blackhole.Z"
        threat_id = "2147605515"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackhole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "strServerClassName" ascii //weight: 1
        $x_1_2 = "=mLG+AM2WQzciR8w" ascii //weight: 1
        $x_1_3 = ":(Ram Disk)" ascii //weight: 1
        $x_1_4 = "Set cdaudio door open" ascii //weight: 1
        $x_1_5 = "brc_Server.exe" ascii //weight: 1
        $x_1_6 = "c:\\brclog.txt" ascii //weight: 1
        $x_10_7 = {0f 84 8e 00 00 00 b8 ?? ?? ?? ?? ba 1c 00 00 00 e8 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 10 01 00 00 c7 05 ?? ?? ?? ?? 02 00 00 00 c7 05 ?? ?? ?? ?? 03 00 00 00 c7 05 ?? ?? ?? ?? e8 03 00 00 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 00 c7 05 ?? ?? ?? ?? 04 00 00 00}  //weight: 10, accuracy: Low
        $x_10_8 = {54 52 65 67 4d 6f 6e 69 74 6f 72 54 68 72 65 61 64 55 8b ec 53 56 57 84 d2 74 08 83 c4 f0 e8 ?? ?? ?? ?? 8b f1 8b da 8b f8 b1 01 33 d2 8b c7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Blackhole_L_2147632992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blackhole.L"
        threat_id = "2147632992"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackhole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "138soft.com/blackhole/verify.asp?md5=" ascii //weight: 1
        $x_1_2 = ":(Ram Disk)" ascii //weight: 1
        $x_1_3 = "BrcServer2.Exe" ascii //weight: 1
        $x_10_4 = {0f 84 8e 00 00 00 b8 ?? ?? ?? ?? ba 1c 00 00 00 e8 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 10 01 00 00 c7 05 ?? ?? ?? ?? 02 00 00 00 c7 05 ?? ?? ?? ?? 03 00 00 00 c7 05 ?? ?? ?? ?? e8 03 00 00 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 00 c7 05 ?? ?? ?? ?? 04 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Blackhole_AB_2147637022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blackhole.AB"
        threat_id = "2147637022"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackhole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 0a 00 00 00 99 f7 f9}  //weight: 1, accuracy: High
        $x_1_2 = {3d 03 01 00 00 74 2c 85 c0 75 47}  //weight: 1, accuracy: High
        $x_1_3 = {83 f8 05 0f 87 ?? 00 00 00 ff 24 85}  //weight: 1, accuracy: Low
        $x_1_4 = {42 6c 61 63 6b 20 48 6f 6c 65 09 01 04 20 50 72 6f 66 65 73}  //weight: 1, accuracy: High
        $x_3_5 = {cd cb b3 f6 5b ba da b6 b4}  //weight: 3, accuracy: High
        $x_1_6 = "ntVersion\\Policies\\WinOldApp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Blackhole_AC_2147642791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blackhole.AC"
        threat_id = "2147642791"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackhole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 2e 74 6d 70 00 53 75 70 65 72 2d 45 43 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 5c 63 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "wghai.com" ascii //weight: 1
        $x_1_4 = {5c 41 76 65 6e 67 65 72 2d 44 65 73 74 72 75 63 74 69 6f 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = "mgmts:{impersonationLevel=impersonate}\").InstancesOf(\"Win32_Processor\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


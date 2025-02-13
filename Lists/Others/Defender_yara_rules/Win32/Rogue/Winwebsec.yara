rule Rogue_Win32_Winwebsec_133077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\PornoTubeXXX\\Antivirus" ascii //weight: 1
        $x_1_2 = ", PornoTubeXXX" ascii //weight: 1
        $x_1_3 = "\\service.exe" ascii //weight: 1
        $x_1_4 = " Antivirus?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2f 61 70 69 2f 73 74 61 74 73 2f 69 6e 73 74 61 6c 6c 2f 00}  //weight: 2, accuracy: High
        $x_2_2 = {54 72 79 69 6e 67 20 75 6e 69 6e 73 74 61 6c 6c 20 6e 6f 74 20 72 65 67 69 73 74 65 72 65 64 20 70 72 6f 67 72 61 6d 00}  //weight: 2, accuracy: High
        $x_2_3 = {73 65 6e 64 49 6e 73 74 61 6c 6c 53 74 61 74 69 73 74 69 63 00}  //weight: 2, accuracy: High
        $x_1_4 = "Start --noscan" ascii //weight: 1
        $x_1_5 = {41 46 46 49 44 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Email address (optional):" ascii //weight: 10
        $x_2_2 = {57 69 6e 77 65 62 53 65 63 75 72 69 74 79 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_2_3 = {00 00 57 69 6e 77 65 62 20 53 65 63 75 72 69 74 79 20 42 55 47}  //weight: 2, accuracy: High
        $x_1_4 = "D5DF7C9D-6069-4552-8B0C-D02A912FC889" wide //weight: 1
        $x_1_5 = "securedigitalpayments*.txt" wide //weight: 1
        $x_1_6 = "system32\\ws.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {69 00 6e 00 3d 00 25 00 73 00 26 00 73 00 74 00 73 00 3d 00 25 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {70 00 68 00 70 00 3f 00 61 00 66 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {66 00 69 00 64 00 3d 00 25 00 73 00 26 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {73 00 6f 00 66 00 74 00 5f 00 63 00 6c 00 65 00 61 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_5 = {74 00 73 00 3d 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {75 00 72 00 6c 00 3d 00 25 00 73 00 26 00 77 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 77 00 65 00 62 00 63 00 65 00 6e 00 74 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {47 00 75 00 61 00 72 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {41 00 75 00 74 00 6f 00 53 00 63 00 61 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {4d 00 69 00 6e 00 52 00 75 00 6e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" wide //weight: 10
        $x_10_2 = "WinwebSecurity.exe" ascii //weight: 10
        $x_10_3 = "eurekalog@email.com" ascii //weight: 10
        $x_10_4 = "BugzReportz@gmail.com" ascii //weight: 10
        $x_1_5 = "SettingsAntiRootkit" ascii //weight: 1
        $x_1_6 = "to obtain an update" wide //weight: 1
        $x_1_7 = "register Windwos Security" ascii //weight: 1
        $x_1_8 = "System Security BUG Report" ascii //weight: 1
        $x_1_9 = "Sorry, sending the message didn't work" ascii //weight: 1
        $x_1_10 = "report as confidential and anonymous" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%ProgramFiles%\\Internet Explorer\\IEXPLORE.EXE" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "\\System Security 2009.lnk" wide //weight: 1
        $x_1_4 = "System Security 2009 Support.lnk" wide //weight: 1
        $x_1_5 = "http://%s/in.php?url=%d&affid=%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 31 52 81 c2 da d4 a6 67 ba 5a 68 eb cf 8d 1d ?? ?? ?? ?? 58 f7 d6 c1 ef 07 8d 1d ?? ?? ?? ?? bf 5f 9b b8 e3 8d 0d ?? ?? ?? ?? 83 f8 0a 0f 82 ?? ?? ?? ?? e9 d3 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/av.exe" ascii //weight: 1
        $x_1_2 = "se\\DownloaderShellcode.pdb" ascii //weight: 1
        $x_1_3 = {5c 54 65 6d 70 6f 72 61 72 79 20 49 6e 74 65 72 6e 65 74 20 46 69 6c 65 73 5c 63 6f 6b 70 65 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Security Shield " ascii //weight: 1
        $x_1_2 = "Spyware found :" ascii //weight: 1
        $x_1_3 = "Peacomm/Downloader" ascii //weight: 1
        $x_1_4 = {76 6b 73 5f 73 63 61 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {58 8d 24 94 ff e0 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 ec 64 6d 02 8d 0a 3e 02 8d 0a 3e 02 8d 0a 3e 1c df 9f 3e 1f 8d 0a 3e 1c df 89 3e 83 8d 0a 3e 1c df 8e 3e 31 8d 0a 3e 25 4b 67 3e 0a 8d 0a 3e 25 4b 71 3e 1f 8d 0a 3e 02 8d 0b 3e 6a 8c 0a 3e}  //weight: 1, accuracy: High
        $x_1_2 = {55 50 58 21 0d 09 08 09 f1 1a 1c 6a 5c ab e5 23}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 6a 01 6a ff 6a 23 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 4d 08 51 (e8|ff 15)}  //weight: 10, accuracy: Low
        $x_1_2 = "%s%s\\smartfortress.exe" ascii //weight: 1
        $x_1_3 = "%s%s\\smartprotection.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 27 00 6d 00 20 00 68 00 65 00 72 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8d 45 f4 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 8b 35 ?? ?? ?? ?? 8b 36 8d 55 f0 b8 ?? ?? ?? ?? ff d6 8b 45 f0 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 01 6a 13 e8 ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 0f b6 c3 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 65 79 3d [0-16] 26 73 74 73 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 01 00 80 6a 00 6a 00 ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 8d 45 f0 ba 05 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 04 00 00 8d 85 ?? ?? ?? ?? 50 8b 45 ec 50 e8 ?? ?? ?? ?? 83 f8 01 1b db 43 84 db 74 0a 83 7d e8 00 0f 87}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 38 50 4b ?? ?? ?? ?? c7 45}  //weight: 10, accuracy: Low
        $x_1_2 = "in.php?url=" wide //weight: 1
        $x_1_3 = "install/" wide //weight: 1
        $x_1_4 = "the latest components.." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f4 03 00 00 0f 83 ?? ?? 00 00 0f b6 55 ?? 85 d2 (75 ??|0f 85 ?? ??) 8b 45 ?? 03 45 ?? 89 45 ?? 6a 0c 8d 4d ?? 51 8b 55 ?? 52 e8 ?? ?? ?? ?? 83 c4 0c 0f 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 01 6a ff 6a 23 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 4d 08 51 (e8|ff 15)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_15
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Total Secure 2009" ascii //weight: 2
        $x_1_2 = {4d 61 6c 77 61 72 65 20 46 6f 75 6e 64 00 00 00 ff ff ff ff 0d 00 00 00 53 70 79 77 61 72 65 20 46 6f 75 6e 64 00 00 00 ff ff ff ff 0d 00 00 00 41 64 77 61 72 65 20 46 6c 6f 75 6e 64}  //weight: 1, accuracy: High
        $x_1_3 = {4d 61 6c 77 61 72 65 00 ff ff ff ff 07 00 00 00 53 70 79 77 61 72 65 00 ff ff ff ff 06 00 00 00 41 64 77 61 72 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_16
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 52 02 e8 ?? ?? ?? ?? ff 75 ?? 68 ?? ?? ?? ?? 8d 45 ?? ba ?? ?? ?? ?? 0f b7 52 08 e8 ?? ?? ?? ?? ff 75 ?? 8d 45 ?? ba}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 06 00 00 00 e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? b9 00 00 00 00 e8 ?? ?? ?? ?? 8b 55 ?? 8d 4d ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 6a ff}  //weight: 1, accuracy: Low
        $x_1_3 = {58 8d 24 94 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_17
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 26 00 61 00 66 00 66 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 4d 00 53 00 41 00 53 00 43 00 75 00 69 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 4c 41 53 54 5f 52 41 4d 5f 53 43 41 4e 5f 54 49 4d 45 00}  //weight: 1, accuracy: High
        $x_1_4 = "Type: Autorun scan" wide //weight: 1
        $x_1_5 = "cmd /C del /F /Q " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_18
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 00 46 00 52 00 4d 00 48 00 41 00 52 00 4d 00 46 00 55 00 4c 00 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 00 4d 00 41 00 47 00 45 00 4c 00 49 00 53 00 54 00 56 00 49 00 52 00 55 00 53 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {4c 00 6f 00 63 00 61 00 6c 00 5c 00 43 00 72 00 79 00 70 00 74 00 6f 00 72 00 54 00 65 00 73 00 74 00 45 00 76 00 65 00 6e 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {49 00 4d 00 41 00 47 00 45 00 4c 00 49 00 53 00 54 00 42 00 54 00 4e 00 53 00 55 00 50 00 45 00 52 00 42 00 49 00 47 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "TFRMBSOD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_19
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 4f 4d 42 41 52 44 41 4d 41 58 49 4d 55 4d 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 61 74 61 3d 25 73 25 73 26 63 72 79 3d 25 64 26 70 6c 63 3d 25 73 26 6e 75 63 3d 25 64 26 77 69 76 3d 25 64 26 69 73 36 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {64 61 74 61 3d 25 73 25 73 26 65 78 63 3d 30 78 25 30 38 58 26 65 72 72 3d 30 78 25 30 38 58 26 63 72 79 3d 25 64 26 70 6c 63 3d 25 73 26 6e 75 63 3d 25 64 26 77 69 76 3d 25 64 26 69 73 36 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 3f 41 56 43 57 41 6c 65 72 74 49 6e 66 65 63 74 40 40 00}  //weight: 1, accuracy: High
        $x_1_5 = {2e 3f 41 56 43 57 41 6c 65 72 74 48 61 72 6d 66 40 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_20
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b3 dc b9 9e f7 bd d7 cd f7 bd d7 cd f7 bd d7 cd e9 ef 42 cd e9 bd d7 cd e9 ef 54 cd 74 bd d7 cd e9 ef 53 cd c4 bd d7 cd d0 7b ba cd ff bd d7 cd d0 7b ac cd ec bd d7 cd f7 bd d6 cd 9b bc d7 cd 0b 9d c5 cd f9 bd d7 cd e9 ef 5d cd cc bd d7 cd e9 ef 43 cd f6 bd d7 cd e9 ef 46 cd f6 bd d7 cd 52 69 63 68 f7 bd d7 cd}  //weight: 1, accuracy: High
        $x_1_2 = {4c 01 03 00 57 2e 79 4d 00 00 00 00 00 00 00 00 e0 00 03 01 0b 01 09 00 00 90 04 00 00 20 00 00 00 60 06 00 b0 fc 0a 00 00 70 06 00 00 00 0b 00 00 00 40 00 00 10 00 00 00 02 00 00 05 00 00 00 00 00 00 00 05 00 00 00 00 00 00 00 00 20 0b 00 00 10 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_21
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Windows has detected spyware infection! Click this message to install the last update of Windows security software." ascii //weight: 5
        $x_2_2 = "WARNING: Your computer is infected" ascii //weight: 2
        $x_4_3 = "explorer \"http://go.winantivirus.com" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_22
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 53 6a 03 53 53 6a 50 8d (84 24 ?? ??|44 24 ??) 50 57 ff 15 ?? ?? ?? ?? 8b e8 3b eb 74 ?? 6a 64 ff d6 6a 01}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 00 69 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 75 00 72 00 6c 00 3d 00 [0-6] 26 00 61 00 66 00 66 00 69 00 64 00 3d 00 25 00 77 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2f 00 77 00 73 00 2e 00 7a 00 69 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 00 77 00 73 00 5c 00 25 00 30 00 38 00 64 00 2e 00 25 00 77 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_2_5 = "90BF8224-CD63-4081-A4C7" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_23
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2d 00 70 00 61 00 79 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {8b cb 2b ca 8b 3e 0f b6 4c 0f ff 8b 3e 3a 4c 1f ff 74 06 c6 45 ff 00 eb 04 42 48 75 e3}  //weight: 2, accuracy: High
        $x_8_3 = {b8 01 00 00 00 e8 ?? ?? ?? ?? 8b 45 ?? 8d 55 ?? e8 ?? ?? ?? ?? 8b 45 ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 75 0c e8 ?? ?? ?? ?? 6a 65 e8}  //weight: 8, accuracy: Low
        $x_8_4 = {b8 01 00 00 00 e8 ?? ?? ?? ?? 8b 45 ?? 8d 55 ?? e8 ?? ?? ?? ?? 8b 45 ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 75 [0-48] e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 65 e8}  //weight: 8, accuracy: Low
        $x_8_5 = {b8 01 00 00 00 e8 ?? ?? ?? ?? 8b 45 ?? 8d 55 ?? e8 ?? ?? ?? ?? 8b 45 ?? 50 8d 4d ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ?? 58 e8 ?? ?? ?? ?? 75 [0-32] 6a 65 e8}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((2 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_24
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 8d 45 ?? 50 b9 ?? ?? ?? 00 8b 55 f8 b8 02 00 00 80 e8 ?? ?? ?? ff eb 18 6a 00 8d 45 ?? 50 b9 ?? ?? ?? 00 8b 55 f8 b8 01 00 00 80 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 48 99 f7 7d f0 8b c2 8b 55 f8 0f b6 1c 02 8b 45 fc 0f b6 44 30 ff 32 d8 80 c3 00 8b 45 f4 e8 ?? ?? ?? ff 88 5c 30 ff 46 4f 75 d3 33 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 06 00 00 00 e8 ?? ?? ?? ff 8b 95 ?? ?? ?? ff 8d 85 ?? ?? ?? ff b9 00 00 00 00 e8 ?? ?? ?? ff 8b 95 ?? ?? ?? ff 8d 8d ?? ?? ?? ff b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 95 ?? ?? ?? ff 8d 85 ?? ?? ?? ff e8 ?? ?? ?? ff ff b5 ?? ?? ?? ff 68 ?? ?? ?? 00 8b c3 ba 04 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {43 00 72 00 79 00 74 00 69 00 63 00 61 00 6c 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_25
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 75 08 6a 01 6a ff 6a 23 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 75 08 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = {85 c0 75 09 c7 45 ?? ad fe ad de eb ?? 8d 85 07 00 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {61 00 62 00 6f 00 75 00 74 00 3a 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 72 00 69 00 73 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "%s\\payform_%02d.%02d." ascii //weight: 1
        $x_2_5 = {6a 43 6a 00 6a 00 6a 00 6a 00 6a ff 8b 45 f4 ff 70 57 ff 15 ?? ?? ?? ?? 6a 01 8b 45 f4 8b 00 8b 4d f4 ff 50 08 8b 45 f4 8b 00 8b 4d f4 ff 10 6a 00}  //weight: 2, accuracy: Low
        $x_1_6 = {81 7d f8 09 10 00 00 0f 84 8a 01 00 00 83 7d f8 42 77 55 83 7d f8 42 0f 84 ea 01 00 00 83 7d f8 33 0f 84 10 02 00 00 83 7d f8 34 0f 84 13 02 00 00 83 7d f8 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_26
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a 2a 2a 20 4e 54 46 53 2e 53 59 53 20 2d 20 41 64 64 72 65 73 73 20 30 78 46 42 46 45 37 36 31 37 20 62 61 73 65 20 61 74 20 30 78 46 44 33 30 39 34 43 32 2c 20 44 61 74 65 53 74 61 6d 70 20 33 64 36 61 62 65 66 66 00}  //weight: 1, accuracy: High
        $x_1_2 = {54 68 69 73 49 73 50 61 79 46 6f 72 6d 43 6c 61 73 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "detected a potential hazard (TrojanSPM/LX) on your computer" ascii //weight: 1
        $x_1_4 = {57 4e 44 53 2d 54 47 4e 31 35 2d 52 46 46 32 39 2d 41 41 53 44 4a 2d 41 53 44 36 35 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 79 73 69 6e 3d 25 73 26 70 72 6f 63 6c 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 64 62 67 2e 70 68 70 3f 61 66 66 69 64 3d 25 73 26 68 3d 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_27
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 00 65 00 67 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 48 00 4b 00 43 00 55 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 20 00 2f 00 76 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 00 73 00 74 00 73 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 00 69 00 6e 00 73 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = ".billingsoftware" ascii //weight: 1
        $x_1_6 = "inspectguide.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_28
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 57 69 6e 77 65 62 53 65 63 75 72 69 74 79 5c 57 69 6e 77 65 62 53 65 63 75 72 69 74 79 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 00 63 00 74 00 69 00 76 00 61 00 74 00 65 00 20 00 57 00 69 00 6e 00 77 00 65 00 62 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 4e 00 6f 00 77 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 00 68 00 69 00 73 00 20 00 66 00 69 00 6c 00 65 00 20 00 6d 00 61 00 79 00 20 00 63 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 20 00 64 00 61 00 67 00 65 00 72 00 6f 00 75 00 73 00 20 00 63 00 6f 00 64 00 65 00 20 00 61 00 6e 00 64 00 20 00 73 00 65 00 72 00 69 00 6f 00 73 00 6c 00 79 00 20 00 64 00 61 00 6d 00 61 00 67 00 65 00 20 00 79 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 2e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_29
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 00 73 00 00 00 [0-24] 74 00 73 00 3d 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {72 00 65 00 67 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 48 00 4b 00 43 00 55 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 20 00 2f 00 76 00 [0-80] 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 [0-38] 2e 00 65 00 78 00 65 00 [0-21] 2f 00 69 00 6e 00 73 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 62 00 61 00 74 00 [0-20] 3a 00 74 00 72 00 79 00 [0-20] 64 00 65 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_30
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 40 0c 72 00 61 00 8b 45 fc c7 40 10 74 00 69 00 8b 45 fc c7 40 14 6f 00 6e 00 8b 45 fc c7 40 18 20 00 65 00 8b 45 fc c7 40 1c 2d 00 6d 00 8b 45 fc c7 40 20 61 00 69 00 8b 45 fc c7 40 24 6c 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {83 7d 0c 00 74 7c 81 7d 0c cd cd cd cd 74 73 81 7d 0c 0d f0 ad ba 74 6a}  //weight: 1, accuracy: High
        $x_2_3 = "PCID:%05u%08X" ascii //weight: 2
        $x_1_4 = "%s%s&dx=1" ascii //weight: 1
        $x_1_5 = {6d 73 77 75 75 69 5f 63 6c 61 73 73 00 00 00 00 2e 65 78 65 00 00 00 00 [0-4] 25 73 25 73 5c 25 73 2e 65 78 65 00 25 73 25 73 00}  //weight: 1, accuracy: Low
        $x_1_6 = {25 73 2a 00 25 73 25 73 5c 25 73 2e 69 63 6f 00 31 00 00 00 6d 73 77 75 75 69 5f 63 6c 61 73 73 00}  //weight: 1, accuracy: High
        $x_2_7 = {25 73 25 73 5c 73 79 73 74 65 6d 70 72 6f 74 65 63 74 69 6f 6e 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_2_8 = "=IHDRt)=IDATt)=PLTEt)=IENDt)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_31
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 00 63 00 77 00 61 00 6c 00 65 00 72 00 74 00 70 00 61 00 79 00 00 00 73 00 63 00 77 00 61 00 6c 00 65 00 72 00 74 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 00 00 73 00 63 00 77 00 61 00 6c 00 65 00 72 00 74 00 68 00 61 00 72 00 6d 00 66 00 75 00 6c 00 00 00 73 00 63 00 77 00 61 00 6c 00 65 00 72 00 74 00 69 00 6e 00 66 00 65 00 63 00 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {52 00 45 00 47 00 49 00 53 00 54 00 52 00 41 00 54 00 49 00 4f 00 4e 00 20 00 45 00 2d 00 4d 00 41 00 49 00 4c 00 00 00 4f 00 52 00 44 00 45 00 52 00 20 00 23 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 00 57 00 41 00 4c 00 45 00 52 00 54 00 42 00 52 00 4f 00 57 00 53 00 4e 00 41 00 4d 00 45 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 00 69 00 6d 00 61 00 67 00 65 00 20 00 69 00 63 00 6f 00 6e 00 3a 00 25 00 75 00 20 00 69 00 63 00 6f 00 6e 00 78 00 3a 00 32 00 36 00 20 00 69 00 63 00 6f 00 6e 00 79 00 3a 00 34 00 36 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_32
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "inspectguide.com" ascii //weight: 1
        $x_1_2 = {01 10 0d 38 1b 07 1d 14 49 2e 0a 0b 3e}  //weight: 1, accuracy: High
        $x_1_3 = {66 89 54 70 fe 46 4f 75 04 01 01 01 01 c7 c4 c0 bd}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b6 1c 02 8b 45 fc 0f b6 44 38 ff 32 d8 8b 45 f4 e8 ?? ?? ?? ?? 88 5c 38 ff 47 4e 75 d6}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 5c 32 ff 8b 55 f8 0f b6 04 02 32 d8 80 c3 00 8b 45 f4 e8 ?? ?? ?? ?? 88 5c 30 ff 46 4f 75 d0}  //weight: 1, accuracy: Low
        $x_1_6 = {b8 02 00 00 80 e8 ?? ?? ?? ?? 8b d8 84 db 75 3c 80 7d ?? 00 74 1c 6a 02 8d 45 ?? 50 ba ?? ?? ?? ?? 8b 4d fc b8 01 00 00 80}  //weight: 1, accuracy: Low
        $x_1_7 = {ba 06 00 00 00 e8 ?? ?? ?? ?? 8b 55 e0 8d 45 e4 b9 00 00 00 00 e8 ?? ?? ?? ?? 8b 55 e4 8d 4d e8 b8 ?? ?? 53 00 e8 ?? ?? ?? ?? 8b 55 e8 8d 45 ec}  //weight: 1, accuracy: Low
        $x_1_8 = {0f b7 52 02 e8 ?? ?? ?? ?? ff 75 ?? 68 ?? ?? ?? ?? 8d 45 ?? ba ?? ?? ?? ?? 0f b7 52 08 e8 ?? ?? ?? ?? ff 75 ?? 8d 45 ?? ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_33
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 69 6d 6c 53 68 69 65 6c 64}  //weight: 1, accuracy: High
        $x_1_2 = {10 69 6d 6c 46 75 6c 6c 50 72 6f 74 65 63 74 65 64}  //weight: 1, accuracy: High
        $x_1_3 = {0d 69 6d 6c 47 75 61 72 64 4c 65 76 65 6c}  //weight: 1, accuracy: High
        $x_1_4 = {0e 69 6d 6c 50 61 79 46 6f 72 6d 4c 6f 67 6f}  //weight: 1, accuracy: High
        $x_3_5 = {8d 55 f6 8d 44 58 fe b9 02 00 00 00 e8 ?? ?? ?? ?? 66 03 02 02 02 81 6d 83 6d ff 4d f6}  //weight: 3, accuracy: Low
        $x_1_6 = {0c 74 62 53 79 73 74 65 6d 53 63 61 6e}  //weight: 1, accuracy: High
        $x_1_7 = {0c 50 72 6f 74 65 63 74 4c 65 76 65 6c}  //weight: 1, accuracy: High
        $x_1_8 = {0a 56 69 72 75 73 46 6f 75 6e 64}  //weight: 1, accuracy: High
        $x_1_9 = {07 50 61 79 46 6f 72 6d}  //weight: 1, accuracy: High
        $x_2_10 = "/c taskkill /f /pid" wide //weight: 2
        $x_1_11 = "i'm here" wide //weight: 1
        $x_2_12 = {6a 00 6a 01 6a 13 e8 ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 0f b6 c3 50 e8}  //weight: 2, accuracy: Low
        $x_2_13 = {33 f6 8b c6 99 f7 ff 8b 45 ?? 0f b6 04 10 30 03 43 46 49 75 ed}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_34
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 31 30 31 00 00 00 00 42 49 4e 41 52 59 00}  //weight: 1, accuracy: High
        $x_1_2 = {42 49 4e 41 52 59 00 00 23 31 30}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 08 81 f9 4d 5a 00 00 75 ?? 8b 55 ?? 8b 45 ?? 03 42 3c 89 45 ?? 8b 4d ?? 81 39 50 45 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 40 68 00 30 00 00 68 ?? ?? 00 00 6a 00 ff 15 ?? ?? ?? ?? 89 45 ?? c7 45}  //weight: 1, accuracy: Low
        $x_3_5 = {8a 02 88 45 ?? 0f bf 4d ?? 0f b6 54 0d ?? 0f be 45 ?? 33 c2 88 45 ?? 8b 4d ?? 8a 55 ?? 88 11 66 8b 45 ?? 66 83 c0 01 66 89 45 ?? 0f bf 4d ?? 83 f9 05 75 06}  //weight: 3, accuracy: Low
        $x_4_6 = {6a 40 0f 1f ?? ?? ?? ?? ?? 68 00 30 00 00 0f 1f ?? ?? ?? ?? ?? 68 ?? ?? 00 00 0f 1f ?? ?? ?? ?? ?? 6a 00 [0-8] ff 15}  //weight: 4, accuracy: Low
        $x_3_7 = {68 4b 1a 00 00 [0-9] 6a 00 [0-9] ff 15 ?? ?? ?? ?? [0-9] 89 45 41 00 [0-58] 6a 40 [0-9] 68 00 30 00 00}  //weight: 3, accuracy: Low
        $x_1_8 = {0f 70 ca 00}  //weight: 1, accuracy: High
        $x_5_9 = {33 d2 66 8e e8 66 8c ea d1 ea 72 f9 66 8e e8 66 8c e8 e8 00 00 00 00 58 83 c0 10 03 c2 8d 00 ff e0}  //weight: 5, accuracy: High
        $x_5_10 = {0f 77 0f 6f 4d ?? 0f 6f 55 ?? 0f 70 ca 00 0f fc d1 0f ef d1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            ((1 of ($x_4_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_35
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 10 66 3b 11 75 1e 66 85 d2 74 15 66 8b 50 02 66 3b 51 02 75 0f 83 c0 04 83 c1 04 66 85 d2 75 de}  //weight: 1, accuracy: High
        $x_1_2 = {38 39 34 35 33 31 35 2d 36 35 34 38 34 33 31 00}  //weight: 1, accuracy: High
        $x_1_3 = "/api/stats/install/" ascii //weight: 1
        $x_1_4 = "&lid=<VERSION>&affid=" wide //weight: 1
        $x_1_5 = {62 00 73 00 6f 00 64 00 5f 00 64 00 65 00 73 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "bcdedit.exe -set TESTSIGNING ON" ascii //weight: 1
        $x_1_7 = {00 68 61 72 6d 66 75 6c 00 [0-32] 65 6e 67 2e 6c 6e 67 00}  //weight: 1, accuracy: Low
        $x_1_8 = {2e 3f 41 56 43 57 41 6c 65 72 74 49 6e 66 65 63 74 40 40 00}  //weight: 1, accuracy: High
        $x_1_9 = {47 00 65 00 74 00 4d 00 61 00 78 00 56 00 69 00 72 00 75 00 73 00 43 00 6f 00 75 00 6e 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {43 00 41 00 76 00 65 00 72 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 53 00 65 00 76 00 65 00 6e 00 41 00 63 00 74 00 69 00 6f 00 6e 00 43 00 65 00 6e 00 74 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {41 00 6c 00 6c 00 20 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 20 00 63 00 68 00 61 00 6e 00 67 00 65 00 73 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 64 00 69 00 73 00 63 00 61 00 72 00 64 00 65 00 64 00 2e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_36
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 3e 50 4b 01 02 74 0a b8 f6 ff ff ff}  //weight: 2, accuracy: High
        $x_2_2 = {81 38 50 4b 01 02 74 0c c7 45 ?? f6 ff ff ff}  //weight: 2, accuracy: Low
        $x_2_3 = {8b cb 2b ca 8b 3e 0f b6 4c 0f ff 8b 3e 3a 4c 1f ff 74 06 c6 45 ff 00 eb 04 42 48 75 e3}  //weight: 2, accuracy: High
        $x_8_4 = {6a 03 6a 00 8d 8d ?? ?? ff ff ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 ?? ?? ff ff e8 ?? ?? ?? ?? 50 6a 50 (8b|a1 ?? ?? ?? ??) [0-2] e8 ?? ?? ?? ?? 50 8b 45 ?? 50 e8}  //weight: 8, accuracy: Low
        $x_10_5 = {b9 1a 00 00 00 ba 27 00 00 00 e8 ?? ?? ?? ?? b2 01 e8 ?? ?? ?? ?? 8b f8 8b 03 89 78 38 8b c7 b2 01 e8 ?? ?? ?? ?? 8b 03 8b 40 30 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 2f 00 00 00 ba 27 00 00 00 e8 ?? ?? ?? ?? b2 01}  //weight: 10, accuracy: Low
        $x_10_6 = {b9 1a 00 00 00 ba 27 00 00 00 e8 ?? ?? ?? ?? b2 01 e8 ?? ?? ?? ?? 8b 55 ?? 8b 12 89 42 38 8b 45 ?? 8b 00 8b 40 38 b2 01 e8 ?? ?? ?? ?? 8b 45 ?? 8b 00 8b 40 30 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 2f 00 00 00 ba 27 00 00 00 e8}  //weight: 10, accuracy: Low
        $x_10_7 = {b9 1a 00 00 00 ba 27 00 00 00 e8 ?? ?? ?? ?? b2 01 e8 ?? ?? ?? ?? 8b f8 8b 03 89 78 38 8b c7 b2 01 e8 ?? ?? ?? ?? 8b 03 8b 40 1c ba ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 44 00 00 00 ba 27 00 00 00 e8}  //weight: 10, accuracy: Low
        $x_10_8 = {b9 1a 00 00 00 ba 27 00 00 00 e8 ?? ?? ?? ?? b2 01 e8 ?? ?? ?? ?? 8b 55 ?? 8b 12 89 42 38 8b 45 ?? 8b 00 8b 40 38 b2 01 e8 ?? ?? ?? ?? 8b 45 ?? 8b 00 8b 40 1c ba ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 44 00 00 00 ba 27 00 00 00 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_37
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "This version of Windows Security is for evaluating purposes only. The removal features are disabled. You may scan your PC to locate malware/spyware threats." ascii //weight: 1
        $x_1_2 = "please stay connected to the Internet, turn off your firewall and enter the Registration key you recived." ascii //weight: 1
        $x_1_3 = "To be able to remove threats, you should register Windwos Security." ascii //weight: 1
        $x_1_4 = "actShowAlertHarmfulExecute" ascii //weight: 1
        $x_1_5 = "chkSettingsAntiRootkitClick(" ascii //weight: 1
        $x_1_6 = "btnPayClick" ascii //weight: 1
        $x_1_7 = "!chkSettingsAdvancedDetectionClick%" ascii //weight: 1
        $x_1_8 = "WSAlertSecurity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_38
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "359F5809-00B8-4455-A73A-9EA62A51101B" wide //weight: 1
        $x_1_2 = "CD950FCD-42AE-4AFB-86A9-B9793B57900B" wide //weight: 1
        $x_1_3 = {2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 70 00 68 00 70 00 3f 00 61 00 66 00 66 00 69 00 64 00 3d 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 70 00 68 00 70 00 3f 00 61 00 66 00 66 00 69 00 64 00 3d 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2f 00 70 00 76 00 2e 00 70 00 68 00 70 00 3f 00 61 00 66 00 66 00 69 00 64 00 3d 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {7a 00 70 00 6d 00 75 00 77 00 62 00 74 00 71 00 71 00 77 00 6b 00 77 00 2e 00 6e 00 65 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {25 00 73 00 25 00 73 00 2e 00 67 00 6c 00 75 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {68 02 00 00 80 e8 ?? ?? ?? ?? 89 45 ?? f6 45 ?? 80 0f 94 c0 f6 d8 1b c0 89 45 ?? 83 7d ?? 00 (0f 84 ?? ??|74 ??) 83 7d ?? 00 75}  //weight: 1, accuracy: Low
        $x_1_9 = {74 73 6a 64 ff d7 6a 01 68 00 00 40 84 8d 44 24 ?? 50 8d 84 24 ?? ?? 00 00 50 53 8d 84 24 ?? ?? 00 00 50 68 ?? ?? ?? ?? 55 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_Winwebsec_133077_39
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {81 38 50 4b 01 02 74 0c c7 45 ?? f6 ff ff ff}  //weight: 3, accuracy: Low
        $x_3_2 = "1. Connecting to the server..." wide //weight: 3
        $x_3_3 = "2. Checking for the latest components..." wide //weight: 3
        $x_3_4 = "3. Downloading the latest components..." wide //weight: 3
        $x_3_5 = "System Security" wide //weight: 3
        $x_3_6 = "install/installpv.exe" wide //weight: 3
        $x_1_7 = "73C286B6-0510-4873-AAA5-50E33C080999" wide //weight: 1
        $x_1_8 = "D0150938-650C-45CB-B239-5F3BF52AE600" wide //weight: 1
        $x_1_9 = "CDDAC378-D3AA-4945-A78C-353B6BC6494E" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_40
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 41 52 4e 49 4e 47 21 00 [0-4] 53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 63 6f 6d 65 6e 64 61 74 69 6f 6e 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 6f 72 6d 00 00 00 00 52 6f 67 75 65 00 00 00 44 69 61 6c 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 63 61 6e 6e 69 6e 67 00 00 00 00 50 61 74 68 00 00 00 00 49 6e 66 65 63 74 69 6f 6e 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 68 61 72 6d 66 75 6c 00 [0-32] 65 6e 67 2e 6c 6e 67 00}  //weight: 1, accuracy: Low
        $x_2_6 = {83 f8 01 75 2a 6a 23 8b 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 04 0f b6 ?? 85 ?? 75 0d e8 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_7 = "data=%s%s&plc=%s&nuc=%d&wiv=%d&is6=%d" ascii //weight: 2
        $x_2_8 = {83 f8 01 0f 85 ?? ?? 00 00 6a 23 8b 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 04 0f b6 ?? 85 ?? 0f 85 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_1_9 = {57 4e 44 53 2d 54 47 4e 31 35 2d 52 46 46 32 39 2d 41 41 53 44 4a 2d 41 53 44 36 35 00}  //weight: 1, accuracy: High
        $x_1_10 = {41 41 41 41 2d 42 42 42 42 42 2d 43 43 43 43 43 2d 44 44 44 44 44 2d 45 45 45 45 45 00}  //weight: 1, accuracy: High
        $x_1_11 = {2e 3f 41 56 43 57 41 6c 65 72 74 49 6e 66 65 63 74 40 40 00}  //weight: 1, accuracy: High
        $x_2_12 = {8b 45 fc 83 c0 01 89 45 fc 6a 23 8b 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 f8 83 7d fc 00 74 20 8b 4d f8 51 e8 ?? ?? ?? ?? 83 c4 04 0f b6 d0 85 d2 75 0d}  //weight: 2, accuracy: Low
        $x_1_13 = {2e 3f 41 56 43 57 41 6c 65 72 74 48 61 72 6d 66 40 40 00}  //weight: 1, accuracy: High
        $x_1_14 = {50 43 49 44 3a 25 58 00 25 73 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_15 = {25 73 25 73 5c 25 73 2e 65 78 65 00 25 73 25 73 00 00 00 00 56 4d 77 61 72 65 56 4d 77 61 72 65 00}  //weight: 1, accuracy: High
        $x_1_16 = {49 00 44 00 49 00 5f 00 46 00 41 00 4b 00 45 00 00 00}  //weight: 1, accuracy: High
        $x_2_17 = {50 6a 01 6a ff 6a 23 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 4d 08 51 (e8|ff 15)}  //weight: 2, accuracy: Low
        $x_1_18 = {25 73 2a 00 25 73 25 73 5c 6c 69 76 65 73 70 2e 65 78 65 00 25 73 25 73 5c 25 73 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_41
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 63 20 63 6f 6e 66 69 67 20 77 69 6e 64 65 66 65 6e 64 20 73 74 61 72 74 3d 20 64 69 73 61 62 6c 65 64 0d 0a}  //weight: 10, accuracy: High
        $x_10_2 = {6e 00 56 00 69 00 72 00 73 00 5f 00 43 00 6c 00 61 00 73 00 73 00 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {61 00 72 00 61 00 6e 00 74 00 69 00 6e 00 65 00 4c 00 69 00 73 00 74 00 5f 00 43 00 6c 00 61 00 73 00 73 00 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {c7 85 ac fe ff ff 72 63 3d 22 c7 85 b0 fe ff ff 72 65 73 3a c7 85 b4 fe ff ff 2f 2f 69 65 c7 85 b8 fe ff ff 66 72 61 6d c7 85 bc fe ff ff 65 2e 64 6c c7 85 c0 fe ff ff 6c 2f 72 65 c7 85 c4 fe ff ff 64 5f 73 68 c7 85 c8 fe ff ff 69 65 6c 64 c7 85 cc fe ff ff 2e 70 6e 67 c7 85 d0 fe ff ff 22 20 62 6f}  //weight: 10, accuracy: High
        $x_10_5 = {67 00 72 00 6f 00 75 00 70 00 3d 00 00 00 00 00 26 00 65 00 6d 00 61 00 69 00 6c 00 3d 00 00 00 3c 00 00 00 26 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 70 00 75 00 72 00 63 00 68 00 61 00 73 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_5_6 = {26 00 61 00 66 00 66 00 69 00 64 00 3d 00 00 00 26 00 64 00 78 00 3d 00 30 00 00 00}  //weight: 5, accuracy: High
        $x_1_7 = {69 00 6e 00 76 00 6f 00 69 00 63 00 65 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 73 00 61 00 76 00 65 00 64 00 20 00 6f 00 6e 00 20 00 79 00 6f 00 75 00 72 00 20 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 20 00 59 00 6f 00 75 00 20 00 63 00 61 00 6e 00 20 00 70 00 72 00 69 00 6e 00 74 00 20 00 69 00 74 00 20 00 6f 00 75 00 74 00 20 00 6e 00 6f 00 77 00 20 00 69 00 66 00 20 00 6e 00 65 00 63 00 65 00 73 00 73 00 61 00 72 00 79 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {79 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 27 00 73 00 20 00 69 00 6e 00 74 00 65 00 67 00 72 00 61 00 74 00 65 00 64 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 73 00 74 00 61 00 74 00 75 00 73 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {77 00 61 00 69 00 74 00 20 00 61 00 20 00 66 00 65 00 77 00 20 00 73 00 65 00 63 00 6f 00 6e 00 64 00 73 00 20 00 77 00 68 00 69 00 6c 00 65 00 20 00 74 00 68 00 65 00 20 00 70 00 61 00 79 00 6d 00 65 00 6e 00 74 00 20 00 70 00 61 00 67 00 65 00 20 00 6c 00 6f 00 61 00 64 00 73 00 2e 00 2e 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {57 00 61 00 72 00 6e 00 69 00 6e 00 67 00 21 00 20 00 55 00 6e 00 61 00 62 00 6c 00 65 00 20 00 74 00 6f 00 20 00 72 00 65 00 70 00 61 00 69 00 72 00 3a 00 20 00 58 00 58 00 58 00 20 00 74 00 68 00 72 00 65 00 61 00 74 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {59 00 6f 00 75 00 72 00 20 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 20 00 6c 00 65 00 76 00 65 00 6c 00 20 00 70 00 75 00 74 00 73 00 20 00 79 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 61 00 74 00 20 00 72 00 69 00 73 00 6b 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = "Warning! The site you are trying to visit may harm your computer!" wide //weight: 1
        $x_10_13 = {c7 85 ac fe ff ff 73 72 63 3d c7 85 b0 fe ff ff 22 72 65 73 c7 85 b4 fe ff ff 3a 2f 2f 69 c7 85 b8 fe ff ff 65 66 72 61 c7 85 bc fe ff ff 6d 65 2e 64 c7 85 c0 fe ff ff 6c 6c 2f 72 c7 85 c4 fe ff ff 65 64 5f 73 c7 85 c8 fe ff ff 68 69 65 6c c7 85 cc fe ff ff 64 2e 70 6e}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_42
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 00 69 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 61 00 66 00 66 00 69 00 64 00 3d 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = "Software\\Security Tool\\" wide //weight: 2
        $x_2_3 = "TfrmInfectedSoftware" wide //weight: 2
        $x_1_4 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 6c 00 79 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "taskkill /im " wide //weight: 1
        $x_2_6 = {56 00 69 00 72 00 75 00 73 00 46 00 6f 00 75 00 6e 00 64 00 00 00}  //weight: 2, accuracy: High
        $x_1_7 = {46 00 69 00 72 00 73 00 74 00 52 00 75 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {50 00 72 00 69 00 63 00 61 00 76 00 79 00 00 00}  //weight: 1, accuracy: High
        $x_3_10 = {53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 54 00 6f 00 6f 00 6c 00 00 00 ?? ?? ?? ?? ff ff ff ff 0d 00 00 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 54 00 6f 00 6f 00 6c 00 00 00}  //weight: 3, accuracy: Low
        $x_4_11 = {2e 00 63 00 66 00 67 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff 08 00 00 00 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff 05 00 00 00 30 30 30 30 30 00}  //weight: 4, accuracy: Low
        $x_2_12 = {4e 00 60 00 5e 00 70 00 6d 00 64 00 6f 00 74 00 1b 00 4f 00 6a 00 6a 00 67 00 00 00}  //weight: 2, accuracy: High
        $x_2_13 = "Activate Security Tool ( Recommened )" ascii //weight: 2
        $x_2_14 = {43 00 72 00 79 00 74 00 69 00 63 00 61 00 6c 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00 00 00}  //weight: 2, accuracy: High
        $x_2_15 = {25 00 56 00 49 00 52 00 55 00 53 00 4e 00 41 00 4d 00 45 00 25 00 00 00}  //weight: 2, accuracy: High
        $x_2_16 = "TfrmAntivirus" wide //weight: 2
        $x_3_17 = "%s/buy2.php" wide //weight: 3
        $x_3_18 = "?affid=%s&sts=%s" wide //weight: 3
        $x_2_19 = {52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 20 00 49 00 44 00 20 00 69 00 73 00 20 00 30 00 78 00 34 00 30 00 30 00 30 00 31 00 32 00 31 00 33 00 00 00}  //weight: 2, accuracy: High
        $x_1_20 = {69 00 6e 00 73 00 70 00 65 00 63 00 74 00 67 00 75 00 69 00 64 00 65 00 2e 00 63 00 6f 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_3_21 = {25 00 73 00 2f 00 62 00 75 00 79 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff ?? 00 00 00 32 00 2e 00}  //weight: 3, accuracy: Low
        $x_1_22 = {49 00 6d 00 61 00 67 00 65 00 4c 00 69 00 73 00 74 00 56 00 69 00 72 00 75 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_23 = {25 00 50 00 52 00 4f 00 43 00 45 00 53 00 53 00 4e 00 41 00 4d 00 45 00 25 00 00 00}  //weight: 1, accuracy: High
        $x_1_24 = {73 00 6f 00 66 00 74 00 5f 00 63 00 6c 00 65 00 61 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_25 = "lblUpdateAntivirus" ascii //weight: 1
        $x_1_26 = {2f 00 69 00 6e 00 73 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_27 = {00 00 66 00 66 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_2_28 = "%s/in.php?af" wide //weight: 2
        $x_2_29 = "url=%s&win=%s&sts=%s" wide //weight: 2
        $x_1_30 = {8b 45 f0 8b 40 44 89 85 ?? ?? ff ff c6 85 ?? ?? ff ff 11 8b 45 f0 8b 40 4c 89 85 ?? ?? ff ff c6 85 ?? ?? ff ff 11}  //weight: 1, accuracy: Low
        $x_2_31 = {b9 04 00 00 00 8b 45 f4 e8 ?? ?? ?? ?? 8b 95 ?? ?? ff ff 8d 45 f4 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 00 8b 45 f4 e8 ?? ?? ?? ?? 50 8b 45 ec 50 e8}  //weight: 2, accuracy: Low
        $x_1_32 = {2f 00 70 00 61 00 79 00 66 00 6f 00 72 00 6d 00 2f 00 70 00 61 00 79 00 66 00 6f 00 72 00 6d 00 2e 00 70 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_2_33 = {b9 03 00 00 00 8b 45 e8 e8 ?? ?? ?? ?? 8b 95 ?? ?? ff ff 8d 45 e8 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 00 8b 45 e8 e8 ?? ?? ?? ?? 50 8b 45 e0 50 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_43
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 69 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 75 00 72 00 6c 00 3d 00 [0-6] 26 00 61 00 66 00 66 00 69 00 64 00 3d 00 25 00 77 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 00 69 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 75 00 72 00 6c 00 3d 00 31 00 33 00 30 00 26 00 61 00 66 00 66 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 00 6f 00 75 00 74 00 2e 00 70 00 68 00 70 00 3f 00 61 00 66 00 66 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {2d 00 70 00 61 00 79 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 00 70 00 79 00 77 00 61 00 72 00 65 00 2e 00 49 00 45 00 4d 00 6f 00 6e 00 73 00 74 00 65 00 72 00 2e 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "To be able to remove threats, you should register Windwos Security." ascii //weight: 1
        $x_1_7 = "turn off your firewall and enter the Registration key you recived." ascii //weight: 1
        $x_1_8 = "To register Windows Security click Get Licence." ascii //weight: 1
        $x_1_9 = {57 00 53 00 41 00 6c 00 65 00 72 00 74 00 48 00 61 00 72 00 6d 00 66 00 75 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {4c 00 61 00 6e 00 67 00 73 00 2e 00 75 00 64 00 62 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {73 00 65 00 63 00 75 00 72 00 65 00 64 00 69 00 67 00 69 00 74 00 61 00 6c 00 70 00 61 00 79 00 6d 00 65 00 6e 00 74 00 73 00 2a 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {25 00 77 00 73 00 70 00 63 00 25 00 77 00 73 00 69 00 6e 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_13 = {25 00 77 00 73 00 25 00 77 00 73 00 2e 00 67 00 6c 00 75 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {25 00 77 00 73 00 25 00 77 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_15 = {25 00 77 00 73 00 70 00 63 00 25 00 77 00 73 00 63 00 6e 00 66 00 00 00}  //weight: 1, accuracy: High
        $x_1_16 = {53 00 79 00 73 00 74 00 65 00 6d 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 32 00 30 00 30 00 39 00 00 00}  //weight: 1, accuracy: High
        $x_1_17 = {53 00 79 00 73 00 74 00 65 00 6d 00 20 00 43 00 6c 00 65 00 61 00 72 00 65 00 64 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_18 = {25 00 77 00 73 00 5c 00 25 00 30 00 38 00 64 00 2e 00 25 00 77 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_19 = {48 00 69 00 67 00 68 00 00 00 00 00 48 00 61 00 72 00 6d 00 66 00 75 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_20 = {59 00 6f 00 75 00 20 00 68 00 61 00 76 00 65 00 20 00 61 00 20 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 70 00 72 00 6f 00 62 00 6c 00 65 00 6d 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_21 = "Trojan.Tooso is a trojan which attempts to terminate and delete security related applications." wide //weight: 1
        $x_1_22 = {7b 00 36 00 31 00 38 00 38 00 36 00 46 00 46 00 42 00 2d 00 37 00 36 00 37 00 41 00 2d 00 34 00 45 00 42 00 30 00 2d 00 42 00 38 00 37 00 45 00 2d 00 38 00 37 00 35 00 31 00 44 00 45 00 30 00 41 00 41 00 35 00 46 00 31 00 7d 00 00 00}  //weight: 1, accuracy: High
        $x_1_23 = {7b 00 32 00 34 00 41 00 43 00 32 00 34 00 38 00 31 00 2d 00 30 00 30 00 36 00 38 00 2d 00 34 00 35 00 43 00 41 00 2d 00 38 00 41 00 32 00 33 00 2d 00 32 00 34 00 41 00 34 00 31 00 39 00 39 00 33 00 31 00 39 00 38 00 34 00 7d 00 00 00}  //weight: 1, accuracy: High
        $x_1_24 = {57 00 6f 00 72 00 6d 00 00 00 00 00 52 00 6f 00 67 00 75 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_25 = "settingsantirootkit" ascii //weight: 1
        $x_1_26 = "zpmuwbtqqwkw.net" ascii //weight: 1
        $x_1_27 = {43 00 72 00 79 00 74 00 69 00 63 00 61 00 6c 00 20 00 45 00 72 00 72 00 6f 00 72 00 20 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_28 = {25 00 73 00 25 00 73 00 5c 00 70 00 63 00 25 00 73 00 69 00 6e 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_2_29 = {6a 00 68 60 ea 00 00 8d 45 ?? 8b 55 ?? e8 ?? ?? ?? ?? 8b 45 ?? b1 01 33 d2 e8 ?? ?? ?? ?? 33 c0 5a 59 59}  //weight: 2, accuracy: Low
        $x_2_30 = {69 c0 1c 06 00 00 8b 11 6a 07 05 ?? ?? ?? ?? 50 53 ff 92 ?? ?? 00 00 ff 37 8b 8e ?? ?? 00 00 8b 01 68 ?? ?? ?? ?? 6a 01 ff 90 ?? ?? 00 00 8b 86 ?? ?? 00 00 ff 80 ?? ?? 00 00 6a 0a ff 15}  //weight: 2, accuracy: Low
        $x_1_31 = "TFRALERTSECURITY" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Winwebsec_133077_44
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Winwebsec"
        threat_id = "133077"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Winwebsec"
        severity = "52"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "inAntivirus_Class" wide //weight: 1
        $x_1_2 = ", and enable safe web surfing (recommended)." wide //weight: 1
        $x_1_3 = "RAM scan allows detecting \"bodiless\" viruses" wide //weight: 1
        $x_1_4 = "2014reg\">Activation code</a>" wide //weight: 1
        $x_1_5 = {77 69 6e 64 65 66 65 6e 64 0d 0a 73 63 [0-8] 73 74 6f 70 [0-8] 6d 73 6d 70 73 76 63}  //weight: 1, accuracy: Low
        $x_1_6 = {70 69 6e 67 20 6c 6f 63 61 6c 68 6f 73 74 20 2d 77 20 31 30 30 30 20 2d 6e 20 32 20 3e 20 6e 75 6c 0d 0a 72 65 67 20 64 65 6c 65 74 65 20 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 4d 53 41 53 43 75 69 20 2f 66}  //weight: 1, accuracy: High
        $x_1_7 = "Are you sure to uninstall System Doctor 2014?" wide //weight: 1
        $x_1_8 = "ttenzione! Impossibile da riparare: XXX threats" wide //weight: 1
        $x_1_9 = "Suitable solution found <" wide //weight: 1
        $x_1_10 = "Uninstall\\System Doctor 2014" wide //weight: 1
        $x_1_11 = {66 00 77 00 63 00 70 00 6c 00 75 00 69 00 5f 00 63 00 6c 00 61 00 73 00 73 00 00 00 77 00 73 00 63 00 75 00 69 00 5f 00 63 00 6c 00 61 00 73 00 73 00 00 00 4d 00 53 00 41 00 53 00 43 00 55 00 49 00 5f 00 63 00 6c 00 61 00 73 00 73 00}  //weight: 1, accuracy: High
        $x_1_12 = "critical threats will not be eliminated and your computer will remain unprotected" wide //weight: 1
        $x_1_13 = "protection module is working in limited mode in Express version" wide //weight: 1
        $x_1_14 = "Si prega di attendere alcuni secondi, mentre si carica la pagina di pagamento..." wide //weight: 1
        $x_1_15 = "http://sys-doctor.com" wide //weight: 1
        $x_1_16 = {6e 00 57 00 69 00 6e 00 64 00 6f 00 77 00 5f 00 43 00 6c 00 61 00 73 00 73 00 [0-4] 61 00 72 00 61 00 6e 00 74 00 69 00 6e 00 65 00 5f 00 43 00 6c 00 61 00 73 00 73 00}  //weight: 1, accuracy: Low
        $x_1_17 = {2e 00 69 00 6e 00 00 00 2e 00 6c 00 67 00 00 00 2e 00 69 00 63 00 6f 00 00 00 00 00 2e 00 6d 00 61 00 6e 00 69 00 66 00 65 00 73 00 74 00}  //weight: 1, accuracy: High
        $x_1_18 = "Registration e-mail:</STRONG>" wide //weight: 1
        $x_1_19 = {5c 00 73 00 65 00 72 00 76 00 2e 00 62 00 61 00 74 00 00 00 72 00 75 00 6e 00 61 00 73 00}  //weight: 1, accuracy: High
        $x_1_20 = "Win32/Pameseg.XX is the detection for a fake installer" wide //weight: 1
        $x_1_21 = "glichen Sie sicheres Web-Surfen (empfohlen)." wide //weight: 1
        $x_1_22 = {32 30 31 34 00 00 57 00 69 00 6e 00 33 00 32 00 2f 00 4f 00 70 00 65 00 6e 00 43 00 61 00 6e 00 64 00 79 00 20 00 69 00 73 00}  //weight: 1, accuracy: High
        $x_1_23 = {2d 73 6d 2c 22 20 2f 66 0d 0a 00 5c 00 73 00 65 00 72 00 76 00 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: High
        $x_1_24 = {2d 73 6d 2c 22 20 2f 66 0d 0a 00 50 00 [0-43] 32 30 31 34 00}  //weight: 1, accuracy: Low
        $x_1_25 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 22 20 2f 76 20 00 00 00 00 02 00 32 30 02 00 00}  //weight: 1, accuracy: Low
        $x_1_26 = {61 66 66 69 64 00 00 00 61 67 67 72 00 00 00 00 74 69 6d 65 6f 75 74 00 69 6e 73 74 61 6c 6c 00 70 66 00 00 73 75 70 70 6f 72 74 5f 73 69 74 65 73 00}  //weight: 1, accuracy: High
        $x_1_27 = {20 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 69 00 6e 00 66 00 6f 00 2e 00 75 00 72 00 6c 00 00 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 20 00 50 00 61 00 6e 00 65 00 6c 00 5c 00 64 00 6f 00 6e 00 27 00 74 00 20 00 6c 00 6f 00 61 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_28 = {20 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 2e 00 75 00 72 00 6c 00 00 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 20 00 50 00 61 00 6e 00 65 00 6c 00 5c 00 64 00 6f 00 6e 00 27 00 74 00 20 00 6c 00 6f 00 61 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_29 = {70 00 75 00 72 00 63 00 68 00 61 00 73 00 65 00 20 00 69 00 6e 00 66 00 6f 00 2e 00 68 00 74 00 6d 00 6c 00 00 [0-8] 5c [0-64] 20 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 69 00 6e 00 66 00 6f 00 2e 00 75 00 72 00 6c 00 00 [0-8] 5c 01 20 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 2e 00 75 00 72 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_30 = {70 00 57 00 69 00 6e 00 64 00 6f 00 77 00 5f 00 43 00 6c 00 61 00 73 00 73 00 [0-4] 61 00 72 00 61 00 6e 00 74 00 69 00 6e 00 65 00 5f 00 43 00 6c 00 61 00 73 00 73 00}  //weight: 1, accuracy: Low
        $x_1_31 = {5c 00 70 00 68 00 2e 00 6a 00 70 00 67 00 00 00 77 00 77 00 77 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 00 00 00 00 2d 00 75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 00 00 00 00 2d 00 73 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_32 = "Ignore warnings and visit that site in the current state (not recommended)." wide //weight: 1
        $x_1_33 = {53 00 41 00 53 00 43 00 55 00 49 00 5f 00 63 00 6c 00 61 00 73 00 73 00 00 00 66 00 77 00 63 00 70 00 6c 00 75 00 69 00 5f 00 63 00 6c 00 61 00 73 00 73 00 00 00 77 00 73 00 63 00 75 00 69 00 5f 00 63 00 6c 00 61 00 73 00 73 00}  //weight: 1, accuracy: High
        $x_1_34 = "vrantineList_Class" wide //weight: 1
        $x_1_35 = {41 53 32 30 31 34 00 00 6f 00 70 00 65 00 6e 00 00 00 00 00 5c 00 72 00 72 00 2e 00 62 00 61 00 74 00 00}  //weight: 1, accuracy: High
        $x_1_36 = {74 69 6d 65 6f 75 74 00 69 6e 73 74 61 6c 6c 00 70 66 00 00 73 75 70 70 6f 72 74 5f 73 69 74 65 73}  //weight: 1, accuracy: High
        $x_1_37 = {65 00 78 00 65 00 63 00 3a 00 00 00 3a 00 00 00 73 00 64 00 32 00 30 00 31 00 34 00 72 00 65 00 67 00}  //weight: 1, accuracy: High
        $x_1_38 = {76 62 6f 78 [0-10] 71 65 6d 75 [0-10] 76 6d 77 61 72 65 [0-10] 76 69 72 74 75 61 6c 20 68 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


rule Backdoor_Win32_Zegost_Z_2147629478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.Z"
        threat_id = "2147629478"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 6a 00 68 00 fc ff ff 56 ff 15 ?? ?? ?? ?? 68 00 04 00 00 e8 ?? ?? ?? ?? 83 c4 04 8b f8 8d 44 24 08 6a 00 50 68 00 04 00 00 57 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 7c 57 ff d5 8b f0 83 c4 08 85 f6 0f 84}  //weight: 1, accuracy: High
        $x_1_3 = {c6 44 24 04 53 c6 44 24 05 70 c6 44 24 06 69 c6 44 24 07 64 8b 54 24 04 8d 8e ?? ?? ?? ?? 89 86 ?? ?? ?? ?? c6 44 24 08 65 c6 44 24 09 72}  //weight: 1, accuracy: Low
        $x_1_4 = {7e 3b b9 00 08 00 00 33 c0 8d bc 24 ?? ?? ?? ?? 50 f3 ab 8b 83 ?? ?? ?? ?? 8d 94 24 ?? ?? ?? ?? 68 00 20 00 00 52 50 ff d5 85 c0 7e 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Zegost_B_2147630702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.B"
        threat_id = "2147630702"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 00 02 00 00 72 ?? 3d 08 02 00 00 77 ?? 8b ?? 04 [0-16] c1 ?? 10}  //weight: 2, accuracy: Low
        $x_1_2 = {83 fe 01 0f 82 ?? ?? ?? ?? 81 fe 80 00 00 00 0f 87}  //weight: 1, accuracy: Low
        $x_1_3 = "Gh0st" ascii //weight: 1
        $x_1_4 = {83 c2 0d 52 ff d0 a1 ?? ?? ?? ?? 83 c0 0d 50 ff 15 ?? ?? ?? ?? 83 f8 ff 5f 74 0c 8b 0d ?? ?? ?? ?? c6 41 0c 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_F_2147642128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.F"
        threat_id = "2147642128"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 68 63 70 63 73 76 63 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 34 18 00 00 00 c7 44 24 3c 01 00 01 70 c7 44 24 40 01 00 00 00 c7 44 24 44 94 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {89 86 f4 00 00 00 c7 86 c0 00 00 00 20 00 cc 00 c6 86 b4 00 00 00 01 ff 15 ?? ?? ?? ?? 8b 4c 24 6c 89 86 c4 00 00 00 b8 e8 03 00 00 33 d2 f7 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_2147642130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost"
        threat_id = "2147642130"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "llX%ik\\labolGs%s%" ascii //weight: 1
        $x_1_2 = "k- exe.tsoh" ascii //weight: 1
        $x_1_3 = ".3322.org" ascii //weight: 1
        $x_1_4 = "%sot%%\\System32\\svc%s %s%s%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_2147642130_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost"
        threat_id = "2147642130"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\xhjmjj.dat" ascii //weight: 1
        $x_1_2 = "NetSubKey" ascii //weight: 1
        $x_1_3 = "Referer: http://%s:80/http://%s" ascii //weight: 1
        $x_1_4 = "[CapsLock]" ascii //weight: 1
        $x_1_5 = ":] %s" ascii //weight: 1
        $x_1_6 = ":]%d-%d-%d  %d:%d:%d" ascii //weight: 1
        $x_1_7 = "<Enter>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_G_2147642344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.G"
        threat_id = "2147642344"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 80 f2 ?? 88 10 40 ?? 75 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 00 00 20 03 73 0d 6a 02 56 56 ff 75 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {88 9e b5 00 00 00 c6 45 ?? 48 c6 45 ?? 65 c6 45 ?? 61 c6 45 ?? 72 c6 45 ?? 74}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 73 79 73 6c 6f 67 2e 64 61 74 00 25 64 2e 62 61 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Zegost_H_2147643955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.H"
        threat_id = "2147643955"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b ac 24 18 04 00 00 83 c9 ff 8b fd 33 c0 f2 ae f7 d1 49 89 b4 24 c8 03 00 00 8b c1 89 b4 24 cc 03 00 00}  //weight: 4, accuracy: High
        $x_4_2 = {83 c4 04 c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa b8 56 55 55 55 8b fd f7 6c 24 10 8b c2 c1 e8 1f 03 d0 85 d2}  //weight: 4, accuracy: High
        $x_4_3 = {8b 4c 24 10 8b ea 33 d2 0f be 07 47 8b 44 84 14 3b c6 75 ?? 4a eb ?? c1 e1 06 0b c8 42 83 fa 04}  //weight: 4, accuracy: Low
        $x_4_4 = {8b 86 a4 00 00 00 6a ff 50 c7 44 24 18 03 00 00 00 c6 86 b5 00 00 00 00 e8}  //weight: 4, accuracy: High
        $x_1_5 = "\\kb-x6808125.iso" ascii //weight: 1
        $x_1_6 = "<body><h1>403 Forbidden</h1></body>" ascii //weight: 1
        $x_1_7 = "ThreadKeyLogger" ascii //weight: 1
        $x_1_8 = "ThreadProcessAndAntivirus" ascii //weight: 1
        $x_1_9 = "_wonderful_" ascii //weight: 1
        $x_1_10 = "iamsleeping" ascii //weight: 1
        $x_1_11 = "U09GVFdBUkVcXE1pY3Jvc29mdFxcV2luZG93c1xc" ascii //weight: 1
        $x_1_12 = "c3lzVEVNXFxDdXJyRU5UQ29udHJvbFNldFxcU" ascii //weight: 1
        $x_1_13 = "TWljcm9zb2Z0XE5ldHdvcmtcQ29" ascii //weight: 1
        $x_3_14 = "%s\\kb0x%d~.tmp" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_1_*))) or
            ((2 of ($x_4_*) and 8 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((3 of ($x_4_*) and 4 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_I_2147643993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.I"
        threat_id = "2147643993"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 6c 6f 62 61 6c 5c 47 68 30 73 74 20 25 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 86 b5 00 00 00 00 a1 ?? ?? ?? ?? 85 c0 74 14 83 f8 04 74 0f 83 f8 05 74 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_K_2147648788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.K"
        threat_id = "2147648788"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b2 74 b1 5c 50 c6 44 24 ?? 53 c6 44 24 ?? 6f c6 44 24 ?? 66}  //weight: 1, accuracy: Low
        $x_1_2 = {b2 65 b0 73 51 c6 44 24 ?? 47}  //weight: 1, accuracy: Low
        $x_1_3 = {44 51 c6 44 24 ?? 65 c6 44 24 ?? 62 c6 44 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_K_2147648788_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.K"
        threat_id = "2147648788"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 30 44 40 3d ?? ?? ?? ?? 72 f5}  //weight: 2, accuracy: Low
        $x_2_2 = "hounthickChGetTT" ascii //weight: 2
        $x_1_3 = "\\\\.\\Dark" ascii //weight: 1
        $x_1_4 = "%u.193.%d.%d" ascii //weight: 1
        $x_1_5 = "%s SP%d" ascii //weight: 1
        $x_1_6 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74 00 63 3a 5c [0-3] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_3_7 = {74 23 3d 00 00 00 08 72 07 2d 00 00 00 80 eb 06 8d 04 28 83 c0 02 52 50}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_F_2147648835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.F!dll"
        threat_id = "2147648835"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s/updata.aspx?mac=%s&ver=%s" ascii //weight: 1
        $x_1_2 = "%s/work.aspx?query=%s" ascii //weight: 1
        $x_1_3 = "checkupdate" ascii //weight: 1
        $x_1_4 = "fproxy.dl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_H_2147648837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.H!dll"
        threat_id = "2147648837"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 24 5f 52 61 73 44 65 66 61 75 6c 74 43 72 65 64 65 6e 74 69 61 6c 73 23 30 00 00 52 61 73 44 69 61 6c 50 61 72 61 6d 73 21 25 73 23 30 00 00 44 65 76 69 63 65 00 00 50 68 6f 6e 65 4e 75 6d 62 65 72}  //weight: 2, accuracy: High
        $x_2_2 = "plication Data\\Microsoft\\Network\\Connections\\pbk\\rasphone.pbk" ascii //weight: 2
        $x_1_3 = "\\syslog.dat" ascii //weight: 1
        $x_1_4 = "Applications\\iexplore.exe\\shell\\open\\command" ascii //weight: 1
        $x_1_5 = "Global\\dfg%d8d4g" ascii //weight: 1
        $x_2_6 = {b9 10 00 00 00 33 c0 8d bd ?? ?? ff ff f3 ab c7 85 ?? ?? ff ff 44 00 00 00 c6 45 ?? 57 c6 45 ?? 69 c6 45 ?? 6e c6 45 ?? 53 c6 45 ?? 74}  //weight: 2, accuracy: Low
        $x_1_7 = "EnableAdminTSRemote" ascii //weight: 1
        $x_1_8 = "ShutdownWithoutLogon" ascii //weight: 1
        $x_1_9 = "fDenyTSConnections" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_L_2147648880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.L"
        threat_id = "2147648880"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 00 02 00 00 72 2a 3d 08 02 00 00 77 23 8b ?? 04}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 14 01 80 f2 ?? 88 10 40 ?? 75 f4}  //weight: 2, accuracy: Low
        $x_1_3 = {b0 72 53 88 44 24 ?? 88 44 24 ?? b0 65}  //weight: 1, accuracy: Low
        $x_1_4 = "\\systemwin.log" ascii //weight: 1
        $x_1_5 = {3d b7 00 00 00 74 d3 6a 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 7f 96 98 00 ff 15 ?? ?? ?? ?? eb f3}  //weight: 1, accuracy: Low
        $x_1_6 = {25 73 25 63 25 63 25 69 25 69 25 63 25 69 2e 65 78 65 00 00 5c 63 6d 64 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_M_2147649117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.M"
        threat_id = "2147649117"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {d5 07 66 c7 85 ?? ?? ff ff 07 00 66 c7 85 ?? ?? ff ff 10 00 66 c7 85 ?? ?? ff ff 14 00 66 c7 85 ?? ?? ff ff 00 00 8d 85 ?? ?? ff ff 50}  //weight: 4, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_3 = "ServiceDll" ascii //weight: 1
        $x_1_4 = "\\Parameters" ascii //weight: 1
        $x_1_5 = "Global\\ki%Xll" ascii //weight: 1
        $x_1_6 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_2_7 = {69 70 72 69 70 00 00 00 6e 77 73 61 50 41 67 45 6e 54}  //weight: 2, accuracy: High
        $x_1_8 = "%s\\nt%s.dll" ascii //weight: 1
        $x_1_9 = "Antivirus" ascii //weight: 1
        $x_1_10 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 00 00 00 00 6e 65 74 73 76 63 73}  //weight: 1, accuracy: High
        $x_2_11 = {5c 64 72 69 76 65 72 73 5c 4d 73 52 6d 43 74 72 6c 2e 73 79 73 00 00 00 63 63 65 6e 74 65 72 2e 65 78 65}  //weight: 2, accuracy: High
        $x_1_12 = "\\\\.\\msrmctrlvip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_N_2147649746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.N"
        threat_id = "2147649746"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 c6 44 24 ?? 70 c6 44 24 ?? 69 c6 44 24 ?? 64 8b 54 24 ?? 8d 8e ?? ?? ?? ?? c6 44 24 ?? 65 c6 44 24 ?? 72}  //weight: 2, accuracy: Low
        $x_2_2 = {7e 1a 53 8b 54 24 ?? 8a 1c 11 80 f3 ?? 88 1c 11 41 3b c8 7c ee}  //weight: 2, accuracy: Low
        $x_1_3 = "Spider %d" ascii //weight: 1
        $x_1_4 = {5c 63 6f 6d 5c 73 79 73 6c 6f 67 2e 64 61 74 00 25 73 5c 25 64 2e 62 61 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_O_2147649784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.O"
        threat_id = "2147649784"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {41 c6 44 24 ?? 6e c6 44 24 ?? 67 c6 44 24 ?? 65}  //weight: 3, accuracy: Low
        $x_1_2 = "\\MyInformations.ini" ascii //weight: 1
        $x_1_3 = "%s:\\Program Files\\Common Files\\%c%c%c%c%c%c%c.%c%c%c%c%c" ascii //weight: 1
        $x_1_4 = "%s,CodeMain %s" ascii //weight: 1
        $x_1_5 = {5c 41 6e 67 65 6c 2e 63 63 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 74 65 6d 70 5c 50 6c 67 75 69 6e 73 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_AA_2147651477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AA"
        threat_id = "2147651477"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 73 79 73 6c 6f 67 2e 64 61 74 00 7a 77 67 78}  //weight: 1, accuracy: High
        $x_1_2 = "Applications\\iexplore.exe\\shell\\open\\command" ascii //weight: 1
        $x_1_3 = "_kaspersky" ascii //weight: 1
        $x_1_4 = "DragonNest.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_2147651881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost"
        threat_id = "2147651881"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c6 01 7f c6 45 ?? 6b c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 6e c6 45 ?? 65 c6 45 ?? 6c c6 45 ?? 33 c6 45 ?? 32 c6 45 ?? 2e c6 45 ?? 64 c6 45 ?? 6c c6 45 ?? 6c c6 45 ?? 00 8d 55 ?? 52 ff 15}  //weight: 5, accuracy: Low
        $x_1_2 = "\\Application Data\\Microsoft\\Network\\Connections\\pbk\\rasphone.pbk" ascii //weight: 1
        $x_1_3 = "L$_RasDefaultCredentials#0" ascii //weight: 1
        $x_1_4 = "InstallModule" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_Q_2147653404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.Q"
        threat_id = "2147653404"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c1 be 0a 00 00 00 99 f7 fe 8a 82 ?? ?? ?? ?? 8a 91 ?? ?? ?? ?? 32 d0 88 91 ?? ?? ?? ?? 41 81 f9 ?? ?? ?? 00 7c d9}  //weight: 2, accuracy: Low
        $x_1_2 = "%s\\mt%xm.dll" ascii //weight: 1
        $x_1_3 = "%s\\nt%xz.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_Q_2147653404_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.Q"
        threat_id = "2147653404"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%-24s %-15s" ascii //weight: 1
        $x_1_2 = {b9 00 08 00 00 33 c0 8d bc 24 ?? ?? 00 00 50 f3 ab 8b 83 ?? 00 00 00 8d 94 24 ?? ?? 00 00 68 00 20 00 00 52 50 ff d5 85 c0 7e ?? 8d 8c 24 00 00 00 50 51}  //weight: 1, accuracy: Low
        $x_1_3 = {57 50 ff b6 ?? 00 00 00 ff 15 ?? ?? ?? ?? 80 bd ?? ?? ff ff 05 0f 85 ?? ?? 00 00 38 9d ?? ?? ff ff 74 0d 80 bd 04 ff ff 02 0f 85 ?? ?? 00 00 80 bd 04 ff ff 02 0f 85 ?? ?? 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 59 0f 86}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Zegost_R_2147653533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.R"
        threat_id = "2147653533"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 14 66 8b 07 8b d0 81 e2 00 f0 00 00 66 81 fa 00 a0 74 ?? 66 81 fa 00 30 75 ?? 8b 16 25 ff 0f 00 00 03 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 08 8d 45 d0 6a 00 50 6a 08 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 52 41 52 21 74 11}  //weight: 1, accuracy: Low
        $x_1_3 = {00 25 73 4b 42 25 64 5c 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 4c 24 14 6a 00 68 00 00 00 02 6a 00 6a 00 6a 00 51 ff d0 8b f0 85 f6 0f 84 80 00 00 00 56 ff 15 ?? ?? ?? ?? b9 11 00 00 00 33 c0 8d 7c 24 64 50 f3 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Zegost_S_2147653870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.S"
        threat_id = "2147653870"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VerChk=%d:END|%s" ascii //weight: 1
        $x_1_2 = "%s,ClearSelf %s" ascii //weight: 1
        $x_2_3 = {ff ff 83 fa 53 0f 85 ?? ?? 00 00 0f be 85 ?? ?? ff ff 83 f8 50 0f 85 ?? ?? 00 00 0f be 8d ?? ?? ff ff 83 f9 36 0f 85 ?? ?? 00 00 c6 85 64 ?? ?? ff 53}  //weight: 2, accuracy: Low
        $x_2_4 = {68 04 01 00 00 ff 15 ?? ?? ?? ?? c6 45 f8 25 c6 45 f9 73 c6 45 fa 5c c6 45 fb 25 c6 45 fc 64 c6 45 fd 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_S_2147653870_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.S"
        threat_id = "2147653870"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\update\\HlInit.dat" ascii //weight: 1
        $x_1_2 = {5c 50 6c 75 67 69 6e 5c cb ab bf aa 33 33 38 39 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = "CGh0stView" ascii //weight: 1
        $x_1_4 = {b1 e4 d2 ec 43 43 20 bf c9 d2 d4 d3 d0}  //weight: 1, accuracy: High
        $x_1_5 = "tencent://message/?uin=243107&Site=243107&Menu=yes" ascii //weight: 1
        $x_2_6 = {8a 1c 11 80 c3 7a 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 19 88 1c 11 41 3b c8 7c e1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_T_2147654080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.T"
        threat_id = "2147654080"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\3389.bat" ascii //weight: 1
        $x_1_2 = "Gh0st" ascii //weight: 1
        $x_1_3 = "\\syslog.dat" ascii //weight: 1
        $x_1_4 = "[%02d/%02d/%d %02d:%02d:%02d] (%s)" ascii //weight: 1
        $x_1_5 = "DNAMMOC\\NEPO\\LLEHS\\EXE.EROLPXEI\\SNOITACILPPa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Zegost_U_2147654104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.U"
        threat_id = "2147654104"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 86 e4 00 00 00 5f 8d 32 01 b8 01 00 00 00 5f 5e}  //weight: 2, accuracy: High
        $x_1_2 = {6a 04 50 68 02 10 00 00 68 ff ff 00 00 51 c7 44 24 ?? 00 80 00 00 ff d7 8b 06 8d 54 24 ?? 6a 04 52 68 01 10 00 00 68 ff ff 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "HeartBeat Fail ReConnect.. OK!" ascii //weight: 1
        $x_1_4 = {50 44 46 2d 05 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_V_2147654106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.V"
        threat_id = "2147654106"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Proxy-agent: redapp1e Http Proxy v%.2f%s %s" ascii //weight: 1
        $x_1_2 = "%systemroot%\\system32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_3 = {43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 00 00 7e 4d 48 7a}  //weight: 1, accuracy: High
        $x_1_4 = "_dll_Delete_Me__.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_W_2147655470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.W"
        threat_id = "2147655470"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Paths\\{1b55460a-c650-4bb7-ad7a-63a629dc7d3a}" ascii //weight: 1
        $x_1_2 = "CurrentVersion\\Policies\\Explorer\\Run" ascii //weight: 1
        $x_1_3 = "C:\\Program Files\\a..\\synec.exe" ascii //weight: 1
        $x_1_4 = "C:\\hwsig.dll" ascii //weight: 1
        $x_1_5 = "C:\\haotu.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_X_2147655622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.X"
        threat_id = "2147655622"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 43 52 61 74 00}  //weight: 1, accuracy: High
        $x_2_2 = "LANG:%d|Win %s|%s|%s" ascii //weight: 2
        $x_2_3 = {47 45 54 20 2f 68 2e 67 69 66 3f 70 69 64 20 3d [0-5] 26 76 3d}  //weight: 2, accuracy: Low
        $x_2_4 = "Global\\Gh0st" ascii //weight: 2
        $x_1_5 = "Storm ddos soft" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_2147655953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost"
        threat_id = "2147655953"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 c6 44 24 ?? 68 c6 44 24 ?? 30 c6 44 24 ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = "ddos.hackxk.com" ascii //weight: 1
        $x_1_3 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS" ascii //weight: 1
        $x_1_4 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74 00 47 68 30 73 74 20 55 70 64 61 74 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Zegost_AC_2147656916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AC"
        threat_id = "2147656916"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "155"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {7e 24 8b d1 81 e2 01 00 00 80 79 05 4a 83 ca fe 42 8a 14 31 74 05 80 c2 9c eb 03 80 c2 38 88 14 31}  //weight: 50, accuracy: High
        $x_50_2 = {83 e2 03 89 b4 24 d0 03 00 00 03 c2 8a 54 29 ff c1 f8 02 3a d3 89 b4 24 d4 03 00 00 8d 04 40}  //weight: 50, accuracy: High
        $x_20_3 = "doorname=\"msoecj" ascii //weight: 20
        $x_20_4 = {70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 33 26 64 65 6c 20 22 25 73 22 00 77 73 63 72 69 70 74 2e 65 78 65}  //weight: 20, accuracy: High
        $x_10_5 = "%s\\ms%d.dll" ascii //weight: 10
        $x_5_6 = "R2V0U2hvcnRQYXRoTmFtZUE=" ascii //weight: 5
        $x_5_7 = "Q3JlYXRlRmlsZUE==" ascii //weight: 5
        $x_5_8 = "V2luRXhlYw==" ascii //weight: 5
        $x_5_9 = "TG9hZFJlc291cmNl" ascii //weight: 5
        $x_5_10 = "V3JpdGVGaWxl" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_10_*) and 5 of ($x_5_*))) or
            ((2 of ($x_50_*) and 2 of ($x_20_*) and 3 of ($x_5_*))) or
            ((2 of ($x_50_*) and 2 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_AC_2147656917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AC!dll"
        threat_id = "2147656917"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "185"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {44 49 59 54 43 50 46 6c 6f 6f 64 00 44 49 59 55 44 50 46 6c 6f 6f 64 00 3e 43 4c 49 43 4b 20 4f 50 45 4e 20 50 41 47 45}  //weight: 50, accuracy: High
        $x_50_2 = "MultiTCPFlood" ascii //weight: 50
        $x_20_3 = "aW1nLjUxNzc4ODguY29tOjcwNjY=" ascii //weight: 20
        $x_20_4 = "anMuMjAxMTE2OC5jb206NzA3Nw==" ascii //weight: 20
        $x_20_5 = "d29ya3ByZXNzOC5jb206ODA4MA==" ascii //weight: 20
        $x_20_6 = "c2VuZG15c3FsLmNvbTo4MDgw" ascii //weight: 20
        $x_10_7 = "QXBwbGljYXRpb25zXFxWTXdhcmVIb3N0T3Blbi5leGU=" ascii //weight: 10
        $x_5_8 = "Q3JlYXRlUHJvY2Vzc0FzVXNlckE=" ascii //weight: 5
        $x_5_9 = "U2hlbGxFeGVjdXRlQQ==" ascii //weight: 5
        $x_5_10 = "U2V0U2VjdXJpdHlEZXNjcmlwdG9yRGFjbA==" ascii //weight: 5
        $x_5_11 = "UmVnaXN0ZXJTZXJ2aWNlQ3RybEhhbmRsZXJB" ascii //weight: 5
        $x_5_12 = "SW1tR2V0Q29tcG9zaXRpb25TdHJpbmdB" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 3 of ($x_20_*) and 5 of ($x_5_*))) or
            ((2 of ($x_50_*) and 3 of ($x_20_*) and 1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((2 of ($x_50_*) and 4 of ($x_20_*) and 1 of ($x_5_*))) or
            ((2 of ($x_50_*) and 4 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_AD_2147656985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AD"
        threat_id = "2147656985"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/stub.dat" ascii //weight: 1
        $x_10_2 = {8b d1 83 e2 01 80 fa 01 8a 14 01 75 05 80 f2 ?? eb 03 80 f2 ?? 88 14 01 41 3b ce}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_AD_2147656985_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AD"
        threat_id = "2147656985"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 40 89 44 24 ?? 8a 45 00 3c ?? 74 47 3c 42 74}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 00 08 00 00 33 c0 8d bc 24 ?? ?? 00 00 50 f3 ab 8b 83 ?? ?? 00 00 8d 94 24 ?? ?? 00 00 68 00 20 00 00 52 50 ff d5 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_AE_2147658360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AE"
        threat_id = "2147658360"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {47 c6 45 ed 68 c6 45 ee 30 c6 45 ef 73}  //weight: 2, accuracy: High
        $x_2_2 = {48 c6 44 24 11 61 c6 44 24 12 63 c6 44 24 13 6b c6 44 24 14 65 c6 44 24 15 72 c6 44 24 16 3a}  //weight: 2, accuracy: High
        $x_1_3 = {5c 73 79 73 6c 6f 67 2e 64 61 74 [0-16] 25 64 2e 62 61 6b}  //weight: 1, accuracy: Low
        $x_1_4 = "Global\\UUPP %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_AE_2147658360_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AE"
        threat_id = "2147658360"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {47 c6 45 ed 68 c6 45 ee 30 c6 45 ef 73}  //weight: 2, accuracy: High
        $x_1_2 = {5c 73 79 73 74 65 6d 69 6e 66 6f 2e 6b 65 79 00 25 32 64 25 32 64}  //weight: 1, accuracy: High
        $x_1_3 = {61 50 50 4c 49 43 41 54 49 4f 4e 53 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 5c 53 48 45 4c 4c 5c 4f 50 45 4e 5c 43 4f 4d 4d 41 4e 44 00}  //weight: 1, accuracy: High
        $x_1_4 = {54 65 72 6d 69 6e 61 74 65 54 68 72 65 61 64 00 25 73 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_AF_2147658728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AF"
        threat_id = "2147658728"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 57 69 6e 43 6d 64 65 72 00 [0-5] 53 79 73 74 65 6d 00 00 [0-5] 53 65 63 75 72 69 74 79 00}  //weight: 2, accuracy: Low
        $x_1_2 = {4e 65 74 53 75 62 4b 65 79 00}  //weight: 1, accuracy: High
        $x_2_3 = {5c 78 68 6a 6d 6a 6a 2e 64 61 74 00}  //weight: 2, accuracy: High
        $x_1_4 = "Global\\Net_%d" ascii //weight: 1
        $x_1_5 = {77 69 73 74 65 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = "Http/1.1 403 Forbidden" ascii //weight: 1
        $x_1_7 = "pbk\\rasphone.pbk" ascii //weight: 1
        $x_2_8 = {6a 01 6a 67 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 50 68 ?? ?? ?? ?? ff 15}  //weight: 2, accuracy: Low
        $x_4_9 = {47 c6 44 24 0d 68 c6 44 24 0e 30 c6 44 24 0f 73}  //weight: 4, accuracy: High
        $x_1_10 = {33 c6 44 24 33 32 c6 44 24 34 2e c6 44 24 35 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_AG_2147660060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AG"
        threat_id = "2147660060"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3b 47 65 74 50 75 ?? 81 7b 04 72 6f 63 41 75 ?? 60 8b 75 fc 8b 5e 24}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 00 08 00 00 33 c0 8d bd 00 e0 ff ff f3 ab 6a 00 68 00 20 00 00 8d 8d 00 e0 ff ff 51 8b 95 ?? ?? ff ff 8b 82 ?? 00 00 00 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_AI_2147661742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AI"
        threat_id = "2147661742"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {51 68 02 01 00 00 68 13 08 00 00 52 89 7c 24 30 ff d3 33 c0 6a 00 66 8b 46 12 6a 00 68 04 08 00 00 50 ff d3 5f c6 46 10 00 5b b0 01}  //weight: 3, accuracy: High
        $x_5_2 = {4d 32 36 33 c7 ?? ?? ?? 49 56 33 32 c7 ?? ?? ?? 4d 50 34 32 c7 ?? ?? ?? 63 76 69 64}  //weight: 5, accuracy: Low
        $x_5_3 = {c7 46 2c 0a 00 00 00 c7 46 30 06 00 00 00 c7 46 34 10 27 00 00 e8}  //weight: 5, accuracy: High
        $x_5_4 = "%d%d%d%d%d%d.log" wide //weight: 5
        $x_5_5 = {4d 00 61 00 72 00 6b 00 [0-16] 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 44 00 62 00 78 00 55 00 70 00 64 00 61 00 74 00 65 00 42 00 54 00}  //weight: 5, accuracy: Low
        $x_5_6 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 [0-16] 6b 00 6c 00 2e 00 74 00 6d 00 70 00}  //weight: 5, accuracy: Low
        $x_1_7 = "[Num Lock]" wide //weight: 1
        $x_1_8 = "[Print Screen]" wide //weight: 1
        $x_1_9 = "[Scroll Lock]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_AJ_2147661786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AJ"
        threat_id = "2147661786"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 cc 57 c6 45 cd 49 c6 45 ce 4e c6 45 cf 4d c6 45 d0 4d c6 45 d1 2e c6 45 d2 64 c6 45 d3 6c c6 45 d4 6c}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 70 fd ff ff 53 c6 85 71 fd ff ff 4f c6 85 72 fd ff ff 46 c6 85 73 fd ff ff 54 c6 85 74 fd ff ff 57 c6 85 75 fd ff ff 41 c6 85 76 fd ff ff 52}  //weight: 1, accuracy: High
        $x_1_3 = {43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 4e 65 77 73 25 69 25 69 25 69 2e 64 6f 63 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 5b 43 61 70 73 4c 6f 63 6b 5d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_AK_2147662287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AK"
        threat_id = "2147662287"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#%d<<<<<I@C<<<<<%s!" ascii //weight: 1
        $x_1_2 = {68 00 e9 a4 35 57 66 89 45 ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff 77 c6 85 ?? ?? ff ff 77 88 9d [0-16] c6 84 1d ?? ?? ?? ?? 03 c6 84 1d ?? ?? ?? ?? 63 c6 84 1d ?? ?? ?? ?? 6f c6 84 1d ?? ?? ?? ?? 6d 80 a4 1d ?? ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 45 08 81 7d 08 64 19 00 00 0f 8c ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Zegost_AM_2147662338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AM"
        threat_id = "2147662338"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bb 4e 61 bc 00 c7 44 24 10 00 00 00 00 b9 3f 00 00 00 33 c0 8d bc 24 25 02 00 00 c6 84 24 24 02 00 00 00 f3 ab 66 ab 8d 8c 24 24 02 00 00 68 00 01 00 00 51 aa ff d6 8d 94 24 24 02 00 00 68}  //weight: 2, accuracy: High
        $x_2_2 = {f3 ab 66 ab aa b9 3f 00 00 00 33 c0 8d bc 24 25 01 00 00 c6 84 24 24 01 00 00 00 f3 ab 66 ab bb 01 00 00 00 c7 44 24 10 00 00 00 00 aa e8}  //weight: 2, accuracy: High
        $x_1_3 = {25 73 5c 25 64 5f 74 65 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 75 6e 69 6e 73 74 61 6c 6c 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 76 63 48 6f 73 74 2e 44 4c 4c 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {48 54 54 50 45 58 45 00 5c 75 70 64 61 74 65 2e 74 65 6d 70 [0-4] 5c 63 6f 6d 6d 61 6e 64 2e 70 61 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_AN_2147663046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AN"
        threat_id = "2147663046"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 77 c6 85 ?? ?? ff ff 77 88 9d [0-16] c6 84 1d ?? ?? ?? ?? 03 c6 84 1d ?? ?? ?? ?? 63 c6 84 1d ?? ?? ?? ?? 6f c6 84 1d ?? ?? ?? ?? 6d 80 a4 1d ?? ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 45 08 81 7d 08 64 19 00 00 0f 8c ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c1 6a 03 99 5f f7 ff 8a 04 31 83 fa 01 75 0c 3c 20 7e 15 3c 7f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_AO_2147664546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AO"
        threat_id = "2147664546"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\DarkShell\\DS_Server" ascii //weight: 2
        $x_1_2 = "sese-av.in" ascii //weight: 1
        $x_1_3 = "Client hook free failure" ascii //weight: 1
        $x_1_4 = "(#%d)" ascii //weight: 1
        $x_1_5 = "yktstar" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_AP_2147666251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AP"
        threat_id = "2147666251"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 50 08 88 48 0c 8b c6 8a 08 40 3a cb 75 f9 57 8d}  //weight: 2, accuracy: High
        $x_1_2 = {25 73 2f 63 67 69 2f 63 6f 6d 6d 61 6e 64 2e 61 73 70 3f 68 6f 73 74 6e 61 6d 65 3d 25 73 26 63 6f 6d 6d 61 6e 64 3d 74 65 73 74 26 64 65 6c 3d 64 65 6c 66 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 63 67 69 2f 74 65 78 74 75 70 2e 61 73 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {6f 6e 6c 69 6e 65 2e 61 73 70 3f 68 6f 73 74 6e 61 6d 65 3d 25 73 26 68 74 74 70 74 79 70 65 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = "%s\\system\\%d.txt" ascii //weight: 1
        $x_1_6 = {75 70 66 69 6c 65 00 00 64 6f 77 6e 66 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {68 74 74 70 3a 2f 2f 25 73 2f 63 67 69 2f 25 73 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {5c 68 65 6c 70 6d 73 67 2e 74 65 6d 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_AX_2147679133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AX"
        threat_id = "2147679133"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ">nul del %0 /s/q/a/f" ascii //weight: 1
        $x_1_2 = "Hardware\\Description\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_3 = "microsoft\\windows nt\\currentversion\\winlogon" ascii //weight: 1
        $x_1_4 = "http://%s:%d/%d%s" ascii //weight: 1
        $x_1_5 = {00 53 61 6b 65 72 45 76 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {ff d6 50 ff d7 ff d0 68 7f 03 00 00 6a 00 68 ?? ?? ?? 10 [0-6] ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Zegost_AY_2147682670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.AY"
        threat_id = "2147682670"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 f8 0a 00 00 00 50 53 8d 85 38 fe ff ff 53 50 8d 47 01 50 89 5d fc 89 bd 3c fe ff ff 89 b5 38 fe ff ff ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {63 3a 5c 00 22 25 73 22 2c 75 70 64 61 74 65 00 5c 63 73 72 73 73 2e 65 78 65 00 00 25 73 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 5c 63 73 72 73 73 2e 65 78 65 00 00 22 25 73 22 2c (75 70 64 61|49 6e 69 74 53 6b) [0-4] 63 3a 5c}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 73 74 61 72 74 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 73 5c 64 61 74 61 2e 6d 64 62 00}  //weight: 1, accuracy: High
        $x_1_6 = "TW96aWxsYS80LjAgKGNvbXBhdGlibGUp" ascii //weight: 1
        $x_1_7 = "U09GVFdBUkVcQWhuTGFiXFYzTGl0ZQ==" ascii //weight: 1
        $x_1_8 = {25 73 20 25 73 2c 41 4c 53 54 53 5f 45 78 65 63 75 74 65 41 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_9 = {5c 5c 2e 5c 6d 6f 6f 6e [0-8] 63 6d 64 2e 65 78 65 20 2f 63 20 72 64 20 2f 71 20 2f 73 20 22 63 3a 5c 25 73 22}  //weight: 1, accuracy: Low
        $x_1_10 = "\\6C4DA6FB\\svchsot.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Zegost_A_2147684101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.gen!A"
        threat_id = "2147684101"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WinSta0\\Default" ascii //weight: 1
        $x_1_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 57 49 4e 5d [0-6] 5b 43 54 52 4c 5d}  //weight: 1, accuracy: Low
        $x_1_4 = "%-24s %-15s" ascii //weight: 1
        $x_1_5 = "Http/1.1 403 Forbidden" ascii //weight: 1
        $x_1_6 = "[print screen]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_BE_2147684332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BE"
        threat_id = "2147684332"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 6c 6f 62 61 6c 5c 61 69 72 20 25 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {4b 42 44 4c 6f 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {2c 48 69 67 68 53 79 73 74 65 6d 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {65 78 65 2e 64 6d 63 5c 00}  //weight: 1, accuracy: High
        $x_1_5 = {5b 45 58 45 43 55 54 45 5f 6b 65 79 5d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Zegost_2147684932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost!decr"
        threat_id = "2147684932"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "decr: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows\\DbxUpdateBT\\" wide //weight: 10
        $x_1_2 = "Install" wide //weight: 1
        $x_1_3 = "BTFly.dump" wide //weight: 1
        $x_5_4 = {8a 0c 28 80 f1 ?? 88 0c 28 40 3b c3 7c f2 6a 40 68 00 10 00 00 53 6a 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_BH_2147685064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BH"
        threat_id = "2147685064"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 65 72 43 c7 84 24 ?? 01 00 00 68 6b 3d 25 c7 84 24 ?? 01 00 00 64 3a 45 4e c7 84 24}  //weight: 10, accuracy: Low
        $x_2_2 = {68 b7 0b 00 00 8d 8c 24 ?? ?? 00 00 6a 00 51 66 c7 84 24 ?? ?? 00 00 4c 69 c6 84 24 fe}  //weight: 2, accuracy: Low
        $x_2_3 = {77 6f 77 78 c7 84 24 ?? ?? 00 00 69 61 6f 62 c7 84 24 ?? ?? 00 00 6f 2e 63 6f}  //weight: 2, accuracy: Low
        $x_2_4 = {c7 45 dc 25 73 2d 25 88 5d e1 66 c7 45 e2 58 25 88 5d e5 66 c7 45 e6 58 25 88 5d e9 66 c7 45 ea 58 25}  //weight: 2, accuracy: High
        $x_1_5 = "LINNUX PASSWRO" ascii //weight: 1
        $x_1_6 = "--->To MyServer2010 ^_^ [%d]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_BK_2147686219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BK"
        threat_id = "2147686219"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Print Screen]" ascii //weight: 1
        $x_4_2 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" ascii //weight: 4
        $x_2_3 = "Applications\\iexplore.exe\\shell\\open\\command" ascii //weight: 2
        $x_2_4 = "\\keylog.dat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_BL_2147686276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BL"
        threat_id = "2147686276"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 6a 00 68 00 fc ff ff ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 1c 16 3a 1c 2a 75 ?? 42 3b d1 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {00 50 50 50 50 50 50 00}  //weight: 1, accuracy: High
        $x_1_4 = "rundll32.exe %s,hi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_B_2147686293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.gen!B"
        threat_id = "2147686293"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 01 80 f2 62 88 10 40 ?? 75 f4}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 0f 8a d0 03 c8 80 c2 06 8a 19 32 da 40 3b c6 88 19 7c ec}  //weight: 1, accuracy: High
        $x_1_3 = {83 f8 7f 77 11 83 f8 14 72 0c}  //weight: 1, accuracy: High
        $x_1_4 = "Http/1.1 403 Forbidden" ascii //weight: 1
        $x_1_5 = "mozheUpdate" ascii //weight: 1
        $x_1_6 = {45 6e 61 62 6c 65 64 00 cf fb cf a2 00}  //weight: 1, accuracy: High
        $x_1_7 = {5b 46 31 32 5d 00 00 00 5b 46 31 31 5d}  //weight: 1, accuracy: High
        $x_1_8 = {53 65 72 76 69 63 65 4d 61 69 6e 00 6d 61 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_BO_2147686545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BO"
        threat_id = "2147686545"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 f1 43 c6 45 f2 72 c6 45 f3 65 c6 45 f4 64 c6 45 f5 65 c6 45 f6 6e c6 45 f7 74 c6 45 f8 69 c6 45 f9 61 c6 45 fa 6c c6 45 fb 73 c6 45 fc 23}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 e4 25 c6 45 e5 73 c6 45 e6 25 c6 45 e7 73 c6 45 e8 25 c6 45 e9 73}  //weight: 1, accuracy: High
        $x_1_3 = {89 45 fc c6 45 f0 57 c6 45 f1 69 c6 45 f2 6e c6 45 f3 6c c6 45 f4 6f c6 45 f5 67 c6 45 f6 6f c6 45 f7 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Zegost_BP_2147686576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BP"
        threat_id = "2147686576"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 73 63 00 5b 43 61 70 73 4c 6f 63 6b 5d 00 00 50 61 75 73 65}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 c6 61 88 45 c7 c6 45 c8 46 c6 45 c9 6f 88 45 ca c6 45 cb 64}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 e0 66 c6 45 e1 75 c6 45 e2 63 c6 45 e3 6b c6 45 e4 33 c6 45 e5 36 88 5d e6 c6 45 e7 00 ff 55 b0 6a 64 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_BQ_2147686577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BQ"
        threat_id = "2147686577"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 61 75 73 65 00 00 00 5b 43 61 70 73 4c 6f 63 6b 5d}  //weight: 1, accuracy: High
        $x_1_2 = {ff 68 c6 85 ?? ff ff ff 6f c6 85 ?? ff ff ff 6e c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 2e c6 85 ?? ff ff ff 70 c6 85 ?? ff ff ff 62 c6 85 ?? ff ff ff 6b c6 85 ?? ff ff ff 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 f0 5c c6 45 f1 6f c6 45 f2 75 c6 45 f3 72 c6 45 f4 6c c6 45 f5 6f c6 45 f6 67 c6 45 f7 2e c6 45 f8 64 c6 45 f9 61 c6 45 fa 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_BR_2147686587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BR"
        threat_id = "2147686587"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 ff d6 53 ff d6 8d 87 80 00 00 00 68 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {57 ff d6 8a 03 57 32 45 13 02 45 13 88 03 43 ff d6}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 56 ff 77 50 ff 77 34 ff d3 89 45 fc 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_BS_2147686601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BS"
        threat_id = "2147686601"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 45 6e 74 65 72 5d 00 5b 45 53 43 5d 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 d4 5c c6 45 d5 78 c6 45 d6 78 c6 45 d7 6f c6 45 d8 6f c6 45 d9 78 c6 45 da 78 c6 45 db 2e c6 45 dc 4c c6 45 dd 4f c6 45 de 47}  //weight: 1, accuracy: High
        $x_1_3 = {ff 77 c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 5c c6 85 ?? ?? ff ff 54 c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 5c c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_C_2147686622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.gen!C"
        threat_id = "2147686622"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 2e c6 85 ?? ?? ff ff 70 c6 85 ?? ?? ff ff 62}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 5c c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 63}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 2e c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 6c}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 53 c6 85 ?? ?? ff ff 4f c6 85 ?? ?? ff ff 46}  //weight: 1, accuracy: Low
        $x_1_5 = {ff 5c c6 85 ?? ?? ff ff 41 c6 85 ?? ?? ff ff 70}  //weight: 1, accuracy: Low
        $x_1_6 = {ff 5c c6 85 ?? ?? ff ff 4d c6 85 ?? ?? ff ff 69}  //weight: 1, accuracy: Low
        $x_10_7 = {00 5b 43 61 70 73 4c 6f 63 6b 5d 00}  //weight: 10, accuracy: High
        $x_10_8 = "WinSta0\\Default" ascii //weight: 10
        $x_10_9 = "%-24s %-15s" ascii //weight: 10
        $x_10_10 = "http/1.1 403 forbidden" ascii //weight: 10
        $x_10_11 = "pbk\\rasphone.pbk" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_BU_2147686634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BU"
        threat_id = "2147686634"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 c4 80 74 ?? 6a 14 ff 15 ?? ?? ?? 00 66 85 c0 74 ?? 83 ff ff 7e ?? 83 fe 40 7e ?? 83 fe 5b 7d 10}  //weight: 1, accuracy: Low
        $x_1_2 = {68 04 01 00 00 50 c6 44 24 18 5c c6 44 24 1a 75 c6 44 24 1b 72 c6 44 24 1c 6c c6 44 24 1e 67 c6 44 24 1f 2e}  //weight: 1, accuracy: High
        $x_1_3 = {8a 08 83 c1 fe 83 f9 0d 0f 87 ?? ?? 00 00 ff 24 8d ?? ?? 40 00 40 8b ce 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_BV_2147686659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BV"
        threat_id = "2147686659"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 73 63 00 5b 43 61 70 73 4c 6f 63 6b 5d 00 00 50 61 75 73 65}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 d8 47 c6 45 d9 68 c6 45 da 30 c6 45 db 73}  //weight: 1, accuracy: High
        $x_1_3 = {ff 5c c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_BW_2147686661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BW"
        threat_id = "2147686661"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[Print Screen]" ascii //weight: 1
        $x_1_2 = "WinSta0\\Default" ascii //weight: 1
        $x_1_3 = "%-24s %-15s" ascii //weight: 1
        $x_1_4 = {8a 14 01 80 f2 ?? 88 10 40 ?? 75 f4}  //weight: 1, accuracy: Low
        $x_2_5 = {47 c6 44 24 ?? 68 c6 44 24 ?? 30 c6 44 24 ?? 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_BX_2147686663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BX"
        threat_id = "2147686663"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "winsta0\\default" ascii //weight: 1
        $x_1_2 = "fDenyTSConnections" ascii //weight: 1
        $x_1_3 = {00 5b 43 61 70 73 4c 6f 63 6b 5d 00}  //weight: 1, accuracy: High
        $x_1_4 = "pbk\\rasphone.pbk" ascii //weight: 1
        $x_1_5 = {ff 2e c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_BY_2147686692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BY"
        threat_id = "2147686692"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\syslog.dat" ascii //weight: 1
        $x_1_2 = {54 61 62 00 43 6c 65 61 72}  //weight: 1, accuracy: High
        $x_1_3 = "winsta0\\default" ascii //weight: 1
        $x_1_4 = "http/1.1 403 forbidden" ascii //weight: 1
        $x_1_5 = "%s sp%d" ascii //weight: 1
        $x_1_6 = {ff 5c c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Zegost_C_2147686701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.C!dll"
        threat_id = "2147686701"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {58 80 34 11 19 41 3b c8 7c e5}  //weight: 2, accuracy: High
        $x_2_2 = {8d 8e b0 00 00 00 c6 44 24 ?? 47 c6 44 24 ?? 68 c6 44 24 ?? 30 c6 44 24 ?? 73}  //weight: 2, accuracy: Low
        $x_1_3 = "Global\\Torrent %d" ascii //weight: 1
        $x_1_4 = "Fuck_kav_rising" ascii //weight: 1
        $x_1_5 = "RegQueryValueEx(Svchost\\netsvcs)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_D_2147686702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.D!dll"
        threat_id = "2147686702"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 64 ff d6 a1 ?? ?? ?? 10 83 f8 03 74 05 83 f8 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 04 3d 0f 01 00 00 74 0b 3d 02 01 00 00 0f 85 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 1c 11 80 f3 19 88 1c 11 41 3b c8 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_BZ_2147686706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.BZ"
        threat_id = "2147686706"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 5b 63 61 70 73 6c 6f 63 6b 5d 00}  //weight: 1, accuracy: High
        $x_1_2 = "winsta0\\default" ascii //weight: 1
        $x_1_3 = "fdenytsconnections" ascii //weight: 1
        $x_1_4 = "http/1.1 403 forbidden" ascii //weight: 1
        $x_1_5 = {25 73 20 73 70 25 64 00 32 30 31 32}  //weight: 1, accuracy: High
        $x_1_6 = "rdpwd\\Tds\\tcp" ascii //weight: 1
        $x_1_7 = "pbk\\rasphone.pbk" ascii //weight: 1
        $x_1_8 = {ff 53 c6 85 ?? ?? ff ff 4f c6 85 ?? ?? ff ff 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Zegost_CB_2147687867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CB"
        threat_id = "2147687867"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {47 c6 44 24 ?? 68 c6 44 24 ?? 30 c6 44 24 ?? 73 8b 54 24 ?? 8d 8e ?? ?? 00 00 89 86 ?? ?? 00 00 b0 74}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 54 24 04 8a 1c 11 80 c3 ?? 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 ?? 88 1c 11 41 3b c8 7c e1}  //weight: 2, accuracy: Low
        $x_2_3 = {c6 06 6a 8b 13 89 56 01 8b 43 04 8d 56 09 68 f7 1f 00 00 52 57 89 46 05 ff 15}  //weight: 2, accuracy: High
        $x_1_4 = "Global\\mouse %d" wide //weight: 1
        $x_1_5 = "Gh0st Update" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_CC_2147687868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CC"
        threat_id = "2147687868"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 1c 11 80 c3 ?? 88 1c 11 8b [0-3] 8a 1c 11 80 f3 ?? 88 1c 11 41 3b c8 7c}  //weight: 4, accuracy: Low
        $x_4_2 = {8d 8e b0 00 00 00 89 86 ac 00 00 00 b0 74 14 00 [0-7] 47 c6 [0-3] 68 c6 [0-3] 30 c6 [0-3] 73}  //weight: 4, accuracy: Low
        $x_3_3 = {d5 07 66 c7 44 24 ?? 04 00 66 c7 44 24 ?? 13 00 66 c7 44 24 ?? 10 00 66 c7 44 24 ?? 0e 00 ff 15}  //weight: 3, accuracy: Low
        $x_2_4 = {b0 73 53 8b 5d 20 88 45 ?? c6 45 ?? 79 88 45 ?? c6 45 ?? 74 c6 45 ?? 65 c6 45 ?? 6d}  //weight: 2, accuracy: Low
        $x_3_5 = {53 65 6c 66 5f 55 70 64 61 74 65 [0-5] 61 50 50 4c 49 43 41 54 49 4f 4e 53 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 5c 53 48 45 4c 4c 5c 4f 50 45 4e 5c 43 4f 4d 4d 41 4e 44}  //weight: 3, accuracy: Low
        $x_1_6 = "Fuck_avp" ascii //weight: 1
        $x_1_7 = "Global\\Torrent %d" ascii //weight: 1
        $x_1_8 = "\\LogOfSystem.key" ascii //weight: 1
        $x_1_9 = "yek.metsySfOgoL\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_CD_2147687869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CD"
        threat_id = "2147687869"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "svchost.dll" ascii //weight: 10
        $x_10_2 = "kaspersky" wide //weight: 10
        $x_10_3 = "Gh0st Update" wide //weight: 10
        $x_10_4 = "CreateRemoteThread" ascii //weight: 10
        $x_10_5 = "WriteProcessMemory" ascii //weight: 10
        $x_1_6 = "OpenSCManagerW" ascii //weight: 1
        $x_1_7 = "GET %s HTTP/1.0" ascii //weight: 1
        $x_1_8 = "%s\\shell\\open\\command" wide //weight: 1
        $x_1_9 = "Applications\\iexplore.exe\\shell\\open\\command" wide //weight: 1
        $x_1_10 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_CE_2147687870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CE"
        threat_id = "2147687870"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ResetSSDT" ascii //weight: 10
        $x_10_2 = "Gh0st Update" ascii //weight: 10
        $x_10_3 = "ServiceDll" ascii //weight: 10
        $x_10_4 = "%s\\%sex.dll" ascii //weight: 10
        $x_10_5 = "netsvcs_0x%d" ascii //weight: 10
        $x_10_6 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 10
        $x_1_7 = "OpenSCManager" ascii //weight: 1
        $x_1_8 = "SetSecurityDescriptorControl" ascii //weight: 1
        $x_1_9 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_CF_2147687873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CF"
        threat_id = "2147687873"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 47 68 30 73 74 44 6f 63 00 00 00 43 47 68 30 73 74 56 69 65 77 00 00 [0-255] 51 51 57 72 79 2e 44 61 74}  //weight: 1, accuracy: Low
        $x_1_2 = {47 68 30 73 74 20 52 41 54 20 45 78 63 65 70 74 69 6f 6e 00 43 52 41 53 48 20 43 4f 44 45 3a 30 78 25 2e 38 78 20 41 44 44 52 3d 30 78 25 2e 38 78 20 46 4c 41 47 53 3d 30 78 25 2e 38 78 20 50 41 52 41 4d 53 3d 30 78 25 2e 38 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CG_2147687874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CG"
        threat_id = "2147687874"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d fc 80 04 11 da 03 ca 8b 4d fc 80 34 11 29 03 ca 42 3b d0 7c e9}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 f4 48 c6 45 f5 61 c6 45 f6 63 c6 45 f7 6b c6 45 f8 65 c6 45 f9 72}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 c6 50 c6 45 c7 72 c6 45 c8 6f c6 45 c9 63 c6 45 ca 65 c6 45 cb 73 c6 45 cc 73 c6 45 cd 49 c6 45 ce 64 88 5d cf ff d6 50 ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CG_2147687874_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CG"
        threat_id = "2147687874"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Gh0st Update" ascii //weight: 10
        $x_1_2 = "SYSTEM\\CurrentControlSet\\Ser" ascii //weight: 1
        $x_1_3 = "\\install.dat" ascii //weight: 1
        $x_1_4 = "\\syslog.dat" ascii //weight: 1
        $x_1_5 = "ServiceDll" ascii //weight: 1
        $x_1_6 = "StartServiceA" ascii //weight: 1
        $x_1_7 = "WinSta0\\Default" ascii //weight: 1
        $x_1_8 = "\\shell\\open\\command" ascii //weight: 1
        $x_1_9 = "svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_10 = {4e 6f 2d 61 64 64 00 00 bd f8 c8 eb 6c 6f 67 69 6e 00 00 00 25 73 20 25 64 00}  //weight: 1, accuracy: High
        $x_1_11 = {d7 bc b1 b8 b7 a2 cb cd c9 cf cf df d0 c5 cf a2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 53 56 43 53 48 4f 53 54 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_CH_2147688671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CH"
        threat_id = "2147688671"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 3d 7e 00 75 02 33 c0 8a 1e 8b d0 81 e2 ff ff 00 00 8a 54 54 0c 32 d1 32 d3 40 f6 d2 88 16 41 46 66 3b cf 72 da}  //weight: 2, accuracy: High
        $x_1_2 = {c6 85 38 ff ff ff 47 c6 85 39 ff ff ff 65 c6 85 3a ff ff ff 74 c6 85 3b ff ff ff 49 c6 85 3c ff ff ff 6e c6 85 3d ff ff ff 70 c6 85 3e ff ff ff 75 c6 85 3f ff ff ff 74 c6 85 40 ff ff ff 53 c6 85 41 ff ff ff 74 c6 85 42 ff ff ff 61 c6 85 43 ff ff ff 74 c6 85 44 ff ff ff 65 c6 85 45 ff ff ff 00 ff d6 8b 1d ?? ?? ?? ?? 50 ff d3}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 44 24 0c 44 c6 44 24 0f 50 c6 44 24 10 72 c6 44 24 11 6f c6 44 24 12 78 c6 44 24 13 79 c6 44 24 14 4f c6 44 24 15 70 c6 44 24 16 65 c6 44 24 17 6e c6 44 24 18 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CI_2147688817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CI"
        threat_id = "2147688817"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c ping 127.0.0.1 -n 2&%s \"%s\"" ascii //weight: 1
        $x_1_2 = "%s \"%s\",CreateFlashAdapter %s" ascii //weight: 1
        $x_1_3 = " %.2fms, " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CI_2147688817_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CI"
        threat_id = "2147688817"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "aHR0cDovL2" ascii //weight: 8
        $x_4_2 = "ltZy4yMDExMTY4LmNvbS90ZW1wL2kwLmpwZw==" ascii //weight: 4
        $x_4_3 = "pzLjIwMTExNjguY29tL3RlbXAvajAuanM=" ascii //weight: 4
        $x_4_4 = "JXN3aW5kb3dzXHN5c3RlbTMyXHJ1bmRsbDMyLmV4ZQ==" ascii //weight: 4
        $x_2_5 = "V1RTR2V0QWN0aXZlQ29uc29sZVNlc3Npb25JZA==" ascii //weight: 2
        $x_2_6 = "V1RTUXVlcnlTZXNzaW9uSW5mb3JtYXRpb25B" ascii //weight: 2
        $x_1_7 = "d2luaW5ldC5kbGw=" ascii //weight: 1
        $x_1_8 = "SW50ZXJuZXRSZWFkRmlsZQ==" ascii //weight: 1
        $x_1_9 = "R2V0U3lzdGVtRGlyZWN0b3J5QQ==" ascii //weight: 1
        $x_1_10 = "QWRkQWNjZXNzQWxsb3dlZEFjZQ==" ascii //weight: 1
        $x_1_11 = "Z2V0aG9zdGJ5bmFtZQ==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_4_*) and 3 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_CJ_2147688865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CJ"
        threat_id = "2147688865"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 77 69 6e 64 6f 77 73 2e 74 64 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = "%s\\%d_ade.aaast" ascii //weight: 1
        $x_1_3 = "Tiya%08dAI" ascii //weight: 1
        $x_2_4 = {8b 55 fc 80 04 11 e9 [0-21] 8b 55 fc 8a 1c 11 80 f3 19 88 1c 11}  //weight: 2, accuracy: Low
        $x_1_5 = {c7 44 24 24 4d 5a 00 00 c7 44 24 1c 90 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CL_2147689005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CL"
        threat_id = "2147689005"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\%c%c%c%c%c.exe" ascii //weight: 1
        $x_1_2 = {25 73 5c 64 61 74 61 2e 6d 64 62 00}  //weight: 1, accuracy: High
        $x_1_3 = "TW96aWxsYS80LjAgKGNvbXBhdGlibGUp" ascii //weight: 1
        $x_1_4 = {54 46 4d 30 4e [0-4] 2f 66 [0-4] 68 6f 73 74 73}  //weight: 1, accuracy: Low
        $x_1_5 = "/www.kl.gz.cn/~glb/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CM_2147689053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CM"
        threat_id = "2147689053"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 f0 86 c6 45 ec 59}  //weight: 1, accuracy: High
        $x_1_2 = {0f be 45 f0 2b d0 8b 4d f4 03 4d fc 88 11 8b 55 f4 03 55 fc 0f be 02 0f be 4d ec 33 c1}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 f0 43 c6 45 f1 6f c6 45 f2 6e c6 45 f3 6e c6 45 f4 65 c6 45 f5 63 c6 45 f6 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CO_2147689201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CO"
        threat_id = "2147689201"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 57 68 dc dd 1a 33 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b f0 c1 ee 1b c1 e0 05 0b f0 0f b6 c1 8a 4a 01 03 c6 42 84 c9 75 e9}  //weight: 1, accuracy: High
        $x_1_3 = {5c 5c 73 65 c7 85 ?? ?? ?? ?? 72 76 2e 74 c7 85 ?? ?? ?? ?? 78 74 00 78 89 4d a8 c7 45 ?? 69 63 65 73 c7 45 ?? 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CP_2147689343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CP"
        threat_id = "2147689343"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 2c 53 75 6e 6e 79 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 7a 37 36 6d 38 76 50 71 39 42 51 49 44 39 50 73 45 76 51 44 38 2b 71 6d 6d 70 37 7a 76 39 72 33 35 37 77 53 66 00}  //weight: 1, accuracy: High
        $x_1_3 = {c6 44 24 38 00 c6 44 24 3c 57 c6 44 24 3d 61 c6 44 24 40 46 c6 44 24 41 6f 88 54 24 42 c6 44 24 43 53 c6 44 24 45 6e c6 44 24 46 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CR_2147689772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CR"
        threat_id = "2147689772"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 c7 fc fe ff 64 c6 85 c8 fc fe ff 2e c6 85 c9 fc fe ff 25 c6 85 ca fc fe ff 64}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 f5 fe ff ff 5c c6 85 f6 fe ff ff 52 c6 85 f7 fe ff ff 75 c6 85 f8 fe ff ff 6e}  //weight: 1, accuracy: High
        $x_1_3 = {67 67 66 25 63 25 63 25 63 25 63 25 63 63 6b 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {7e 4d 00 00 48 7a 00 00 48 41 52 44 57 41 52 45 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CS_2147690877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CS"
        threat_id = "2147690877"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 25 ff ff 00 00 8b 4d 08 03 4d ec 8a 11 32 54 45 f8 8b 45 08 03 45 ec 88 10 66 8b 4d fc 66 83 c1 01}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 d2 33 c6 45 d3 32 c6 45 d4 2e c6 45 d5 64 c6 45 d6 6c c6 45 d7 6c c6 45 d8 00 8d 45 dc 50 8d 4d 90 51 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {00 5c 73 79 73 6c 6f 67 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 47 68 30 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CT_2147691051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CT"
        threat_id = "2147691051"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 25 ff ff 00 00 8b 4d 08 03 4d ec 8a 11 32 54 45 f8 8b 45 08 03 45 ec 88 10 66 8b 4d fc 66 83 c1 01}  //weight: 1, accuracy: High
        $x_1_2 = {00 47 68 30 73 74}  //weight: 1, accuracy: High
        $x_1_3 = {00 5f 6b 61 73 70 65 72 73 6b 79 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 4e 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CU_2147691119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CU"
        threat_id = "2147691119"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 1e 04 ?? 34 ?? 88 04 1e 83 c6 01 3b 75 e8 7c de}  //weight: 1, accuracy: Low
        $x_1_2 = {c8 00 00 00 c6 44 24 ?? 50 c6 44 24 ?? 72 c6 44 24 ?? 6f c6 44 24 ?? 64 c6 44 24 ?? 75 c6 44 24 ?? 63 c6 44 24 ?? 74 c6 44 24 ?? 4e c6 44 24 ?? 61 c6 44 24 ?? 6d c6 44 24 ?? 65 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CV_2147691381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CV"
        threat_id = "2147691381"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 4d fc 03 4d f8 8a ?? 80 ea 86 8b 45 fc 03 45 f8 88 10}  //weight: 3, accuracy: Low
        $x_3_2 = {8b 4d fc 03 4d f8 8a ?? 80 f2 19 8b 45 fc 03 45 f8 88 10}  //weight: 3, accuracy: Low
        $x_1_3 = {83 c4 0c c6 45 ?? 53 c6 45 ?? 41 c6 45 ?? 4d c6 45 ?? 5c c6 45 ?? 53 c6 45 ?? 41 c6 45 ?? 4d c6 45 ?? 5c c6 45 ?? 44 c6 45 ?? 6f c6 45 ?? 6d}  //weight: 1, accuracy: Low
        $x_1_4 = "cmd /c ping 127.0.0 .1 -n 1&del \"%s\"" ascii //weight: 1
        $x_1_5 = "TEsLORTNOcTNERRUc\\metsys" ascii //weight: 1
        $x_1_6 = "DNAMMOC\\NEPO\\LLEHS\\EXE.EROLPXEI\\" ascii //weight: 1
        $x_1_7 = {00 57 48 4d 5f 53 65 72 76 65 72 5f 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_ME_2147692368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.ME"
        threat_id = "2147692368"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c3 58 9e 00 00 6a 01 53 ff d5 5f 5e 5d 5b c2 08 00}  //weight: 1, accuracy: High
        $x_1_2 = "BEIZHU" ascii //weight: 1
        $x_1_3 = "C:\\1.tmp" ascii //weight: 1
        $x_1_4 = "[BACKSPACE]" ascii //weight: 1
        $x_1_5 = "[Print Screen]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_MB_2147692430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.MB"
        threat_id = "2147692430"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 19 32 da 40 3b c6 88 19 7c ec}  //weight: 2, accuracy: High
        $x_2_2 = {4d c6 44 24 ?? 6f c6 44 24 ?? 5a c6 44 24 ?? 68}  //weight: 2, accuracy: Low
        $x_1_3 = {2e 76 69 72 2c 6d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = "%s\\%d_mz.url" ascii //weight: 1
        $x_1_5 = "Global\\zwj %d" ascii //weight: 1
        $x_1_6 = "s%\\secivres\\teslortnoctnerruc\\metsys" ascii //weight: 1
        $x_1_7 = "mozheUpdate" ascii //weight: 1
        $x_1_8 = {66 69 6c 65 3a 43 3a 5c 50 72 6f 67 72 61 7e 31 5c 25 25 50 72 6f 67 72 7e 31 5c 44 45 53 54 2e 42 41 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_MF_2147692431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.MF"
        threat_id = "2147692431"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {57 c6 45 ed 69 c6 45 ee 6e c6 45 ef 64 8b 55 ?? 8d 8e ?? ?? ?? ?? 89 86 ?? ?? ?? ?? b0 73}  //weight: 3, accuracy: Low
        $x_1_2 = {5c 6b 65 79 6c 6f 67 2e 64 61 74 00 25 64 2e 62 61 6b}  //weight: 1, accuracy: High
        $x_1_3 = {6c 6f 67 69 6e 78 78 00 47 6c 6f 62 61 6c 5c 67 75 69 67 65 20 25 64}  //weight: 1, accuracy: High
        $x_1_4 = "rossecorPlartneC\\metsyS\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_CW_2147692432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CW"
        threat_id = "2147692432"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 1c 11 80 c3 ?? 88 1c 11 8b ?? ?? ?? 8a 1c 11 80 f3 ?? 88 1c 11}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 0c 30 80 f1 ?? 88 0c 30 40 3b c7 72 f2}  //weight: 2, accuracy: Low
        $x_1_3 = {0d 0a 3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_MC_2147692495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.MC"
        threat_id = "2147692495"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 1c 01 80 f3 62 88 18 40 ?? 75 f4}  //weight: 2, accuracy: Low
        $x_1_2 = {80 04 11 7a 03 ca 8b 4d ?? 80 34 11 19 03 ca}  //weight: 1, accuracy: Low
        $x_1_3 = {83 f8 7f 77 11 83 f8 14 72 0c}  //weight: 1, accuracy: High
        $x_1_4 = {48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 6e 0d 0a 0d 0a 3c 62 6f 64 79 3e 3c 68 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 68 31 3e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_CX_2147692497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CX"
        threat_id = "2147692497"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 1c 38 8b d1 81 e2 ff ff 00 00 8a 54 54 0c 32 da 41 88 1c 38 40 3b c6 72 de}  //weight: 2, accuracy: High
        $x_2_2 = {8a 1c 01 80 f3 ?? 88 18 40 4a 75 f4}  //weight: 2, accuracy: Low
        $x_1_3 = {0d 0a 3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 5f 6b 61 73 70 65 72 73 6b 79 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 5c 73 79 73 6c 6f 67 2e 64 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_CZ_2147692755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CZ"
        threat_id = "2147692755"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 80 04 11 da 03 ca 8b 4d fc 80 34 11 29 03 ca 42 3b d0 7c e9}  //weight: 1, accuracy: High
        $x_1_2 = "fuck360" ascii //weight: 1
        $x_1_3 = {42 6c 6f 63 6b 49 6e 70 75 74 [0-8] 57 69 6e 6c 6f 67 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = "SYSTEM\\Group\\Group" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Zegost_DA_2147692824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DA"
        threat_id = "2147692824"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 07 4d c6 47 01 5a ff ?? 6a 00 ff ?? 66 81 3f 4d 5a 74}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 00 4d c6 45 01 5a 66 81 7d 00 4d 5a 74}  //weight: 1, accuracy: High
        $x_2_3 = {73 c6 44 24 ?? 25 c6 44 24 ?? 64 c6 44 24 ?? 2e c6 44 24 ?? 76 c6 44 24 ?? 62 c6 44 24 ?? 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_DB_2147693096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DB"
        threat_id = "2147693096"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 11 80 ea ?? 8b 45 fc 03 45 f8 88 10 8b 4d fc 03 4d f8 8a 11 80 f2 ?? 8b 45 fc 03 45 f8 88 10 eb}  //weight: 2, accuracy: Low
        $x_1_2 = {c6 00 4d 8b 4d 08 c6 41 01 5a 8b 55 08 89 55 ec 8b 45 ec 33 c9 66 8b 08 81 f9 4d 5a 00 00 74}  //weight: 1, accuracy: High
        $x_1_3 = {6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 45 52 41 57 54 46 4f 53 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_DD_2147693288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DD"
        threat_id = "2147693288"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "KBDLoger" ascii //weight: 3
        $x_1_2 = "[EXECUTE_key]" ascii //weight: 1
        $x_1_3 = "Global\\airky" ascii //weight: 1
        $x_1_4 = "rundll32.exe \"%s\",HighSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_DD_2147693288_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DD"
        threat_id = "2147693288"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 00 4d c6 45 01 5a 66 81 7d 00 4d 5a 74}  //weight: 1, accuracy: High
        $x_2_2 = {8a 1c 11 80 c3 ?? 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 ?? 88 1c 11 41 3b ?? 7c}  //weight: 2, accuracy: Low
        $x_2_3 = {4b c6 44 24 ?? 52 c6 44 24 ?? 4e c6 44 24 ?? 4c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e}  //weight: 2, accuracy: Low
        $x_1_4 = {55 c6 00 4d c6 40 01 5a 66 81 38 4d 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_DE_2147693627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DE"
        threat_id = "2147693627"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 38 8b d1 81 e2 ff ff 00 00 8a 54 54 0c 32 da 41 88 1c 38 40 3b c6 72 de 5f 5b}  //weight: 1, accuracy: High
        $x_1_2 = {5c c6 44 24 ?? 6f c6 44 24 ?? 75 c6 44 24 ?? 72 c6 44 24 ?? 6c c6 44 24 ?? 6f c6 44 24 ?? 67 c6 44 24 ?? 2e c6 44 24 ?? 64 c6 44 24 ?? 61 c6 44 24 ?? 74 c6 44 24 ?? 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DE_2147693627_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DE"
        threat_id = "2147693627"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 11 32 54 ?? ?? 8b ?? ?? 03 ?? ?? 88 10 66 8b ?? ?? 66 83 c1 01 66 89 ?? ?? eb}  //weight: 2, accuracy: Low
        $x_1_2 = {c6 45 f4 5c c6 45 f5 6f c6 45 f6 75 c6 45 f7 72 c6 45 f8 6c c6 45 f9 6f c6 45 fa 67 c6 45 fb 2e c6 45 fc 64 c6 45 fd 61 c6 45 fe 74 c6 45 ff 00}  //weight: 1, accuracy: High
        $x_1_3 = {fb ff ff 5c c6 85 ?? fb ff ff 6f c6 85 ?? fb ff ff 75 c6 85 ?? fb ff ff 72 c6 85 ?? fb ff ff 6c c6 85 ?? fb ff ff 6f c6 85 ?? fb ff ff 67 c6 85 ?? fb ff ff 2e c6 85 ?? fb ff ff 64 c6 85 ?? fb ff ff 61 c6 85 ?? fb ff ff 74 c6 85 ?? fb ff ff 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_DF_2147694108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DF"
        threat_id = "2147694108"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 c6 8a 44 45 e4 30 01 46 42 3b d7 72}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 f7 48 c6 45 f8 49 c6 45 f9 44 c6 45 fa 45 c6 45 fb 55 c6 45 fc 52 c6 45 fd 4c}  //weight: 1, accuracy: High
        $x_1_3 = "\\\\.\\agmkis2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DG_2147694334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DG"
        threat_id = "2147694334"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 4b 5f 75 73 65 72 47 68 6f 61 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d 08 8a 11 32 55 fc 8b 45 08 88 10 8b 4d 08 8a 11 02 55 fc 8b 45 08 88 10 8b 4d 08 83 c1 01}  //weight: 1, accuracy: High
        $x_1_3 = {83 ec 0c c6 45 ?? 44 c6 45 ?? 6c c6 45 ?? 6c c6 45 ?? 41 c6 45 ?? 75 c6 45 ?? 64 c6 45 ?? 69 c6 45 ?? 6f c6 45 ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DH_2147694407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DH"
        threat_id = "2147694407"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 81 ac 00 00 00 c6 45 ?? 47 c6 45 ?? 68 c6 45 ?? 30 c6 45 ?? 73 8b}  //weight: 2, accuracy: Low
        $x_1_2 = {8a 14 01 80 c2 ?? 80 f2 ?? 88 14 01 [0-3] 3b ce 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {0d 0a 3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DH_2147694407_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DH"
        threat_id = "2147694407"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 80 f2 ?? 88 10 83 c0 01 83 ?? ?? ?? 01 75 ee}  //weight: 1, accuracy: Low
        $x_2_2 = {c7 86 a8 00 00 00 ff ff ff ff c6 45 ?? 47 c6 45 ?? 68 c6 45 ?? 30 c6 45 ?? 73 b3 74}  //weight: 2, accuracy: Low
        $x_1_3 = {0d 0a 3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DJ_2147694702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DJ"
        threat_id = "2147694702"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 73 76 63 63 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 73 65 72 76 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 73 79 73 6c 6f 67 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "nameserver = %s" ascii //weight: 1
        $x_5_5 = {8a 14 08 80 c2 ?? 80 f2 ?? 88 14 08 40 3b c6 7c ef}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_DL_2147695013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DL"
        threat_id = "2147695013"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 08 80 c2 ?? 88 14 08 8b 4c 24 08 8a 14 08 80 f2 ?? 88 14 08 40 3b c6 7c}  //weight: 2, accuracy: Low
        $x_1_2 = {c6 45 00 4d c6 45 01 5a 66 81 7d 00 4d 5a}  //weight: 1, accuracy: High
        $x_2_3 = {51 c6 44 24 ?? 5c c6 44 24 ?? 6f c6 44 24 ?? 75 c6 44 24 ?? 72 c6 44 24 ?? 6c c6 44 24 ?? 6f c6 44 24 ?? 67 c6 44 24 ?? 2e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DM_2147695295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DM"
        threat_id = "2147695295"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 73 76 63 63 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 53 74 61 72 74 75 70 5c 73 65 72 76 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 73 79 73 6c 6f 67 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_5_4 = {0f bc c1 d2 ec f7 d3 0f c8 b7 8c 0f ba f0 ed}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DN_2147695834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DN"
        threat_id = "2147695834"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec 2c 01 00 00 c6 45 ?? 5c c6 45 ?? 6f c6 45 ?? 75 c6 45 ?? 72 c6 45 ?? 6c c6 45 ?? 6f c6 45 ?? 67 c6 45 ?? 2e c6 45 ?? 64 c6 45 ?? 61 c6 45 ?? 74 c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 08 03 8d 70 ff ff ff 8a 11 32 94 45 7c ff ff ff 8b 45 08 03 85 70 ff ff ff 88 10 66 8b 4d ec 66 83 c1 01 66 89 4d ec eb 91}  //weight: 1, accuracy: High
        $x_1_3 = {56 49 50 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 78 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DO_2147696068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DO"
        threat_id = "2147696068"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 8a 14 01 80 f2 ?? 88 10 40 4b 75 f4}  //weight: 1, accuracy: Low
        $x_2_2 = {53 83 c3 00 83 c3 00 83 c4 0a 83 ec 0a 83 c3 00 83 c3 00 32 c0 5b c3}  //weight: 2, accuracy: High
        $x_1_3 = "<H1>403 Forbidden</H1>" ascii //weight: 1
        $x_1_4 = {52 44 50 2d 54 63 70 00 25 64 44 61 79 20 25 64 48 6f 75 72 20 25 64 4d 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DP_2147696198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DP"
        threat_id = "2147696198"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 3e c6 45 ?? 46 c6 45 ?? 55 c6 45 ?? 43 c6 45 ?? 4b c6 45 ?? 33}  //weight: 2, accuracy: Low
        $x_1_2 = {8a 06 32 c2 02 c2 88 06 46 49 75}  //weight: 1, accuracy: High
        $x_1_3 = "%s /v \"%s\\config\\sam\" \"%sdfer.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DQ_2147696267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DQ"
        threat_id = "2147696267"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 80 04 11 ?? 03 ca 8b 4d fc 80 34 11 ?? 03 ca 42 3b d0 7c e9}  //weight: 1, accuracy: Low
        $x_3_2 = {c6 00 4d c6 40 01 5a 66 81 38 4d 5a 0f 85 ?? ?? ?? ?? 8b 70 3c 03 f0 81 3e 50 45 00 00 0f 85}  //weight: 3, accuracy: Low
        $x_1_3 = {33 db c6 45 ?? 5c c6 45 ?? 52 c6 45 ?? 75 c6 45 ?? 25 c6 45 ?? 64 c6 45 ?? 2e c6 45 ?? 45 c6 45 ?? 58 c6 45 ?? 45}  //weight: 1, accuracy: Low
        $x_1_4 = {89 86 ac 00 00 00 c6 45 ?? 4b c6 45 ?? 75 c6 45 ?? 47 c6 45 ?? 6f c6 45 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_DT_2147696469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DT"
        threat_id = "2147696469"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 80 ea ?? 8b 45 fc 03 45 f8 88 10 8b 4d fc 03 4d f8 8a 11 80 f2 ?? 8b 45 fc 03 45 f8 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ec 08 c6 45 ?? 44 c6 45 ?? 6c c6 45 ?? 6c c6 45 ?? 64 c6 45 ?? 64 c6 45 ?? 6f c6 45 ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DU_2147696526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DU"
        threat_id = "2147696526"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 80 04 11 ?? 03 ca 8b 4d fc 80 34 11 ?? 03 ca 42 3b d0 7c e9}  //weight: 1, accuracy: Low
        $x_1_2 = {53 50 c6 45 ?? 48 c6 45 ?? 61 c6 45 ?? 63 c6 45 ?? 6b c6 45 ?? 65 c6 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DA_2147718686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DA!bit"
        threat_id = "2147718686"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 dc 44 6c 6c 46 c7 45 e0 75 55 70 67 c7 45 e4 72 61 64 72 66 c7 45 e8 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 ec 44 68 6c 56 50 56 c7 45 f0 69 70 56 65 c7 45 f4 72 73 66 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CG_2147720993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CG!bit"
        threat_id = "2147720993"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {4b c6 44 24 ?? 52 c6 44 24 ?? 4e c6 44 24 ?? 4c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 14 08 80 c2 ?? 88 14 08 8b 4c 24 08 8a 14 08 80 f2 ?? 88 14 08 40 3b c6 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CH_2147721256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CH!bit"
        threat_id = "2147721256"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 80 ea ?? 8b 45 fc 03 45 f8 88 10 8b 4d fc 03 4d f8 8a 11 80 f2 ?? 8b 45 fc 03 45 f8 88 10 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 f5 67 c6 45 f6 75 c6 45 f7 65 c6 45 f8 73 c6 45 f9 74 c6 45 fa 20 c6 45 fb 2f c6 45 fc 61 c6 45 fd 64 c6 45 fe 64 c6 45 ff 00 6a 00 8d 45 a0 50 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {52 c6 85 7d ?? ?? ?? 69 c6 85 7e ?? ?? ?? 73 c6 85 7f ?? ?? ?? 69 c6 85 80 ?? ?? ?? 6e c6 85 81 ?? ?? ?? 67 c6 85 82 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DF_2147732667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DF!bit"
        threat_id = "2147732667"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 99 f7 f9 8b 74 24 0c 80 c2 ?? 85 f6 76 10 8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 08 53 55 56 66 81 38 4d 5a 57 74 08 5f 5e 5d 33 c0 5b 59 c3 8b 78 3c 03 f8 89 7c ?? 10 81 3f 50 45 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {50 c6 44 24 ?? 44 c6 44 24 ?? 6c c6 44 24 ?? 6c c6 44 24 ?? 46 c6 44 24 ?? 75 c6 44 24 ?? 55 c6 44 24 ?? 70 c6 44 24 ?? 67 c6 44 24 ?? 72 c6 44 24 ?? 61 c6 44 24 ?? 64 c6 44 24 ?? 72 c6 44 24 ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CS_2147732965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CS!bit"
        threat_id = "2147732965"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 8a 4d ?? 8a 10 32 d1 02 d1 88 10 b8 ?? ?? ?? 00 c3}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 10 b9 fe 00 00 00 25 ff 00 00 00 89 65 f0 99 f7 f9 c7 45 ?? 00 00 00 00 80 c2 ?? 88 55}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 56 e4 50 52 ff 55 fc 8b 07 33 c9 43 83 c6 28 66 8b 48 06 3b d9 0f 8c 2b ff ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {8b 0b 8b 41 28 85 c0 74 ?? 03 c6 85 c0 74 [0-48] 6a 00 6a 01 56 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_CJ_2147732969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CJ!bit"
        threat_id = "2147732969"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8a 08 32 4d ?? 02 4d ?? 88 08 b8 ?? ?? ?? 00 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 8b 78 3c 03 f8 81 3f 50 45 00 00 75 34 8b 35 ?? ?? ?? 00 6a 04 68 00 20 00 00 ff 77 ?? ff 77 ?? ff d6}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 65 6c 6c 65 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CK_2147732973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CK!bit"
        threat_id = "2147732973"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 1e 80 f2 ?? 88 14 1e 46 3b f7 7c ee}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 c6 44 ?? ?? 49 c6 44 ?? ?? 6e c6 44 ?? ?? 69 c6 44 ?? ?? 74 c6 44 ?? ?? 5f c6 44 ?? ?? 44 c6 44 ?? ?? 4c c6 44 ?? ?? 4c c6 44 ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4}  //weight: 1, accuracy: High
        $x_1_4 = {80 3c 1e 5c 75 35 56 8d 8d ?? ?? ?? ff 53 51 ff 15 ?? ?? ?? 00 8d 95 ?? ?? ?? ff 6a 00 52 ff 15 ?? ?? ?? 00 83 c4 14 83 f8 ff 75 0f 8d 85 ?? ?? ?? ff 6a 00 50 ff 15 ?? ?? ?? 00 8b fb 83 c9 ff 33 c0 46 f2 ae f7 d1 49 3b f1 72 b4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Zegost_CL_2147732975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CL!bit"
        threat_id = "2147732975"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 8a 08 32 4d 13 02 4d 13 88 08 40 89 45 08}  //weight: 2, accuracy: High
        $x_1_2 = {66 81 38 4d 5a 0f 85 f9 00 00 00 8b 70 3c 03 f0 81 3e 50 45 00 00 0f 85 e8 00 00 00 bf 00 20 00 00 8b 1d ?? ?? ?? 00 6a 04 57 ff 76 ?? ff 76 ?? ff d3}  //weight: 1, accuracy: Low
        $x_1_3 = {03 4d 08 89 45 f4 51 50 e8 ?? ?? ?? 00 8b 45 f4 83 c4 0c 89 46 f8 8b 45 10 ff 45 fc 83 c6 28 8b 00 0f b7 40 06 39 45 fc 7c}  //weight: 1, accuracy: Low
        $x_1_4 = "%ProgramFiles%\\AppPatch\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CM_2147732976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CM!bit"
        threat_id = "2147732976"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7e 11 8a 14 01 80 c2 ?? 80 f2 ?? 88 14 01 41 3b ce 7c ef}  //weight: 10, accuracy: Low
        $x_3_2 = {4c 6f 61 64 65 72 2e 64 6c 6c 00 44 61 74 61}  //weight: 3, accuracy: High
        $x_2_3 = "\\\\.\\dhwrt4" ascii //weight: 2
        $x_2_4 = "QQGame\\xx.dat" ascii //weight: 2
        $x_1_5 = "I am virus! Fuck you" ascii //weight: 1
        $x_1_6 = {43 4f 4d 53 50 45 43 00 5c 53 6f 75 67 6f 75 2e 6b 65 79}  //weight: 1, accuracy: High
        $x_1_7 = {5b 42 61 63 6b 73 70 61 63 65 5d 00 5b 43 61 70 73 20 4c 6f 63 6b 5d}  //weight: 1, accuracy: High
        $x_1_8 = "360sd.exe" ascii //weight: 1
        $x_1_9 = "\\\\.\\PHYSICALDRIVE0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_DG_2147732981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DG!bit"
        threat_id = "2147732981"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 80 f2 ?? 88 10 40 4e 75 f4}  //weight: 1, accuracy: Low
        $x_2_2 = {44 6c 6c 4d 61 69 6e 2e 64 6c 6c 00 53 68 65 6c 6c 65 78 00}  //weight: 2, accuracy: High
        $x_1_3 = "\\Tencent\\Users\\*.*" ascii //weight: 1
        $x_1_4 = "%-24s %-15s" ascii //weight: 1
        $x_1_5 = "Http/1.1 403 Forbidden" ascii //weight: 1
        $x_1_6 = "%SystemRoot%\\system32\\termsrv_t.dll" ascii //weight: 1
        $x_1_7 = {5b 42 41 43 4b 53 50 41 43 45 5d [0-6] 5b 44 45 4c 45 54 45 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_CQ_2147732990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CQ!bit"
        threat_id = "2147732990"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 33 36 30 74 72 61 79 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 1
        $x_1_3 = {00 25 73 5c 25 64 2e 62 61 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00}  //weight: 1, accuracy: High
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = {00 50 6c 75 67 69 6e 4d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CR_2147732991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CR!bit"
        threat_id = "2147732991"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 6a 05 8a 14 16 30 11 59 99 f7 f9 85 d2 75 0f 00 ff 45 ?? 8b 45 ?? 8b 4d ?? 8b 55 ?? 8b 75}  //weight: 1, accuracy: Low
        $x_1_2 = {57 53 c6 45 ?? 4b c6 45 ?? 45 c6 45 ?? 52 c6 45 ?? 4e c6 45 ?? 45 c6 45 ?? 4c c6 45 ?? 33 c6 45 ?? 32 c6 45 ?? 2e c6 45 ?? 64 c6 45 ?? 6c c6 45 ?? 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {66 81 38 4d 5a 0f 85 12 01 00 00 8b 78 3c 03 f8 81 3f 50 45 00 00 0f 85 01 01 00 00 6a 04 68 00 20 00 00 ff 77 50 ff 77 34 ff 55 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_EA_2147733021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.EA!bit"
        threat_id = "2147733021"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 01 c3 8d 55 ?? 52 68 20 01 00 00 8b 45 ?? 50 8b 4d ?? 51 ff 15 ?? ?? 41 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 04 c6 85 ?? ?? ?? ff 33 c6 85 ?? ?? ?? ff 36 c6 85 ?? ?? ?? ff 30 c6 85 ?? ?? ?? ff 6e c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 74 c6 85 ?? ?? ?? ff 6d c6 85 ?? ?? ?? ff 61 c6 85 ?? ?? ?? ff 6e c6 85 ?? ?? ?? ff 2e c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 78 c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 00}  //weight: 1, accuracy: Low
        $x_1_3 = {85 c0 0f 85 ?? ?? 00 00 c6 45 ?? 43 c6 45 ?? 3a c6 45 ?? 5c c6 45 ?? 57 c6 45 ?? 69 c6 45 ?? 6e c6 45 ?? 64 c6 45 ?? 6f c6 45 ?? 77 c6 45 ?? 73 c6 45 ?? 5c c6 45 ?? 73 c6 45 ?? 76 c6 45 ?? 63 c6 45 ?? 68 c6 45 ?? 6f c6 45 ?? 73 c6 45 ?? 74 c6 45 ?? 31 c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78 c6 45 ?? 65 c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" ascii //weight: 1
        $x_1_5 = "AxEeulaVteSgeR" ascii //weight: 1
        $x_1_6 = "C:\\Windows\\System32\\wscript.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Zegost_CI_2147733036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CI!bit"
        threat_id = "2147733036"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10}  //weight: 2, accuracy: High
        $x_2_2 = {4b c6 44 24 ?? 52 c6 44 24 ?? 4e c6 44 24 ?? 4c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 03 8b c8 8b d0 c1 e9 ?? c1 ea ?? 8b f0 83 e1 01 83 e2 01 c1 ee ?? a9 ?? ?? ?? ?? 74 15}  //weight: 1, accuracy: Low
        $x_1_4 = {56 57 8b 78 3c 89 65 f0 03 f8 89 7d e4 81 3f 50 45 00 00 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_CI_2147733036_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CI!bit"
        threat_id = "2147733036"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 80 ea ?? 8b 45 fc 03 45 f8 88 10 8b 4d fc 03 4d f8 8a 11 80 f2 ?? 8b 45 fc 03 45 f8 88 10 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 65 78 00}  //weight: 1, accuracy: High
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 1
        $x_1_4 = "Applications\\iexplore.exe\\shell\\open\\command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DY_2147733060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DY!bit"
        threat_id = "2147733060"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5b 98 cb ee 7d 3a 5d 20 25 73 0d 0a 5b 95 72 e9 67 3a 5d 25 64 2d 25 64 2d 25 64 20 20 25 64 3a 25 64 3a 25 64 0d 0a 00}  //weight: 2, accuracy: High
        $x_2_2 = {5c b3 cc d0 f2 5c c6 f4 b6 af 5c 73 65 72 76 65 72 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_2_3 = "\\Programs\\Startup\\server.exe" ascii //weight: 2
        $x_2_4 = {5c 73 76 63 63 68 6f 73 74 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_1_5 = ".?AVCScreenSpy@@" ascii //weight: 1
        $x_1_6 = "?AVCKeyboardManager@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_CD_2147733081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CD!bit"
        threat_id = "2147733081"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 5d fc c6 45 ?? 56 c6 45 ?? 49 c6 45 ?? 44 c6 45 ?? 3a c6 45 ?? 32 c6 45 ?? 30 c6 45 ?? 31 c6 45}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 f6 6c c6 45 f7 44 c6 45 f8 64 ff 35 ?? ?? ?? ?? c6 45 f9 6f c6 45 fa 73 c6 45 fb 53 c6 45 fc 74 c6 45 fd 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DE_2147733085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DE!bit"
        threat_id = "2147733085"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 5c c6 85 ?? ?? ?? ?? 52 c6 85 ?? ?? ?? ?? 75 c6 85 ?? ?? ?? ?? 25 c6 85 ?? ?? ?? ?? 64 c6 85 ?? ?? ?? ?? 2e c6 85 ?? ?? ?? ?? 45}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 50 c6 85 ?? ?? ?? ?? 6c c6 85 ?? ?? ?? ?? 75 c6 85 ?? ?? ?? ?? 67 c6 85 ?? ?? ?? ?? 69 c6 85 ?? ?? ?? ?? 6e c6 85 ?? ?? ?? ?? 33 c6 85 ?? ?? ?? ?? 32 c6 85 ?? ?? ?? ?? 2e c6 85 ?? ?? ?? ?? 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CP_2147733093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CP!bit"
        threat_id = "2147733093"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows Media Player\\csrss.exe" ascii //weight: 1
        $x_1_2 = {00 50 6c 75 67 69 6e 4d 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 25 73 5c 25 64 2e 62 61 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_SL_2147733099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.SL!bit"
        threat_id = "2147733099"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5c 00 00 00 66 89 45 84 b9 53 00 00 00 66 89 4d 86 ba 74 00 00 00 66 89 55 88 b8 61 00 00 00 66 89 45 8a b9 72 00 00 00 66 89 4d 8c ba 74 00 00 00 66 89 55 8e b8 75 00 00 00 66 89 45 90 b9 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {b9 4a 00 00 00 66 89 4d b0 ba 6f 00 00 00 66 89 55 b2 b8 68 00 00 00 66 89 45 b4 b9 61 00 00 00 66 89 4d b6 ba 6e 00 00 00 66 89 55 b8 33 c0 66 89 45 ba b9 2e 00 00 00 66 89 4d bc ba 65 00 00 00 66 89 55 be b8 78 00 00 00 66 89 45 c0 b9 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8a 1c 30 80 f3 ?? f6 d3 80 f3 ?? 88 1c 30 46 81 fe ?? ?? 00 00 75 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_EF_2147733109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.EF!bit"
        threat_id = "2147733109"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 d0 44 c6 45 d1 6c c6 45 d2 6c c6 45 d3 46 c6 45 d4 75 c6 45 d5 55 c6 45 d6 70 c6 45 d7 67 c6 45 d8 72 c6 45 d9 61 c6 45 da 64 c6 45 db 72 c6 45 dc 73}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 f0 47 c6 45 f1 65 c6 45 f2 74 c6 45 f3 6f c6 45 f4 6e c6 45 f5 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_EG_2147733130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.EG!bit"
        threat_id = "2147733130"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 10 25 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 [0-16] 88 55 fc c7 45 f8 00 00 00 00 eb ?? 8b 55 f8 83 c2 01 89 55 f8 8b 45 f8 3b 45 0c 73 ?? 8b 4d 08 8a 11 32 55 fc 8b 45 08 88 10 8b 4d 08 8a 11 02 55 fc 8b 45 08 88 10 8b 4d 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_CZ_2147735275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.CZ!bit"
        threat_id = "2147735275"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllFuUpgradrs" ascii //weight: 1
        $x_1_2 = {88 54 24 25 c6 44 24 26 6c c6 44 24 28 69 c6 44 24 29 70 88 5c 24 2b 88 4c 24 2c c6 44 24 2d 73 c6 44 24 2e 66 c6 44 24 2f 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_ZG_2147758169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.ZG!MTB"
        threat_id = "2147758169"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 11 32 55 fc 8b 45 08 88 10 8b 4d 08 8a 11 02 55 fc 8b 45 08 88 10 8b 4d 08 8a 11 32 55 fc 8b 45 08 88 10 8b 4d 08 83 c1 01 89 4d 08 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_KM_2147772866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.KM!MTB"
        threat_id = "2147772866"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 04 1e 99 bd db 06 00 00 f7 fd b8 cd cc cc cc 83 c6 01 80 c2 4b 30 14 39 f7 e1 c1 ea 02 8d 04 92 8b d1 2b d0 75 ?? 33 f6 83 c1 01 3b 4c 24 ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 04 1e 99 bd d9 06 00 00 f7 fd 8a 04 39 bd 05 00 00 00 80 c2 4f 32 c2 46 88 04 39 8b c1 99 f7 fd 85 d2 75 ?? 33 f6 8b 44 24 ?? 41 3b c8 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Zegost_GKM_2147779744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.GKM!MTB"
        threat_id = "2147779744"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 0f be 04 3e 99 f7 fd 8b 44 24 ?? 83 c6 01 80 c2 4b 30 91 ?? ?? ?? ?? 8d 94 08 ?? ?? ?? ?? b8 cd cc cc cc f7 e2 c1 ea 02 8d 04 92 8b d1 2b d0 83 c2 02 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_STA_2147780920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.STA"
        threat_id = "2147780920"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\WetFish" ascii //weight: 2
        $x_2_2 = {41 63 74 69 76 65 [0-10] 44 69 73 63 6f 6e 6e 65 74}  //weight: 2, accuracy: Low
        $x_2_3 = {5c 63 66 67 2e 69 6e 69 [0-32] 4b 7a 68 61 75 79}  //weight: 2, accuracy: Low
        $x_2_4 = {48 6f 6f 6b 54 43 50 44 72 69 76 65 72 00}  //weight: 2, accuracy: High
        $x_2_5 = {64 62 67 00 69 64 61 00 61 76 70 00}  //weight: 2, accuracy: High
        $x_3_6 = {8b ce f7 e6 c1 ea 02 8d 04 92 2b c8 f7 d9 1b c9 46 23 f9 81 fe ?? ?? ?? ?? 7c 20 00 47 30 86}  //weight: 3, accuracy: Low
        $x_1_7 = {c7 45 e4 55 53 45 52}  //weight: 1, accuracy: High
        $x_1_8 = {c7 45 f0 77 73 70 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zegost_C_2147794435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.C!MTB"
        threat_id = "2147794435"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f8 03 45 f4 8b 4d 08 0f be 14 01 8b 45 0c 03 45 f4 0f be 08 3b d1}  //weight: 10, accuracy: High
        $x_3_2 = "%s\\SHELL\\OPEN\\COMMAND" ascii //weight: 3
        $x_3_3 = "\\CurrentVersion\\netcache" ascii //weight: 3
        $x_3_4 = "KvMonXP.exe" ascii //weight: 3
        $x_3_5 = "ShutdownWithoutLogon" ascii //weight: 3
        $x_3_6 = "EnableAdminTSRemote" ascii //weight: 3
        $x_3_7 = "DenyTSConnections" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_DF_2147798523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.DF!MTB"
        threat_id = "2147798523"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 44 1e 01 8a 14 39 46 32 d0 8b c1 88 14 39 99 bd 05 00 00 00 f7 fd 85 d2 75 02 33 f6 8b 44 24 18 41 3b c8 7c da}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_GZK_2147813485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.GZK!MTB"
        threat_id = "2147813485"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchsot.exe" ascii //weight: 1
        $x_1_2 = "hanabenk.com" ascii //weight: 1
        $x_1_3 = "epostbenk.go" ascii //weight: 1
        $x_1_4 = "TG9jYWxTaXpl" ascii //weight: 1
        $x_1_5 = "R2V0RElCaXRz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_GJK_2147847943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.GJK!MTB"
        threat_id = "2147847943"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b0 45 b1 52 68 ?? ?? ?? ?? c6 44 24 ?? 47 88 44 24 ?? c6 44 24 ?? 54 c6 44 24 ?? 53 88 44 24 ?? 88 4c 24 ?? c6 44 24 ?? 56 88 44 24 ?? 88 4c 24 ?? c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 30 88 5c 24 ?? e8 ?? ?? ?? ?? 83 c4 04 89 44 24 64 3b c3 c6 84 24}  //weight: 10, accuracy: Low
        $x_1_2 = "programB.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_GKH_2147849938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.GKH!MTB"
        threat_id = "2147849938"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c2 8b f0 33 c9 85 f6 ?? ?? 8d a4 24 ?? ?? ?? ?? b8 ?? ?? ?? ?? f7 e1 8b c2 d1 e8 b2 03 f6 ea 8a d1 2a d0 80 c2 02 00 91 ?? ?? ?? ?? 41 3b ce}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zegost_GNX_2147918284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zegost.GNX!MTB"
        threat_id = "2147918284"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 55 f0 8b 45 08 03 45 f8 8a 0a 32 08 8b 55 0c 03 55 f0 88 0a}  //weight: 5, accuracy: High
        $x_5_2 = {8b ec 83 ec 0c c6 45 f4 44 c6 45 f5 6c c6 45 f6 6c c6 45 f7 53 c6 45 f8 68 c6 45 f9 65 c6 45 fa 6c c6 45 fb 6c c6 45 fc 00 8b 45 08 50}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


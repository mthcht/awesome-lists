rule Trojan_Win32_Hupigon_IF_2147797786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hupigon.IF!MTB"
        threat_id = "2147797786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://182.61.23.215:90/" wide //weight: 1
        $x_1_2 = "lock/checkuid.asp?uid=" wide //weight: 1
        $x_1_3 = "lock/ver.asp?ID=" wide //weight: 1
        $x_1_4 = "down/lock.exe" wide //weight: 1
        $x_1_5 = "Locklist.ini" wide //weight: 1
        $x_1_6 = "lastname=" wide //weight: 1
        $x_1_7 = "namelist=" wide //weight: 1
        $x_1_8 = "dxqt=" wide //weight: 1
        $x_1_9 = "xrjt=" wide //weight: 1
        $x_1_10 = "xrwj=" wide //weight: 1
        $x_1_11 = "zdyname=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hupigon_GME_2147810546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hupigon.GME!MTB"
        threat_id = "2147810546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "167.114.0.144" ascii //weight: 1
        $x_1_2 = "http://www.folder-hider-stealth.com/ip2.shtml" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "Password" ascii //weight: 1
        $x_1_5 = "\\pic.jpg" ascii //weight: 1
        $x_1_6 = "\\www.Bat" ascii //weight: 1
        $x_1_7 = "\\desktop.ini" ascii //weight: 1
        $x_1_8 = "\\dll\\flgf.dll" ascii //weight: 1
        $x_1_9 = "\\extip.txt" ascii //weight: 1
        $x_1_10 = "winsyst32.exe" ascii //weight: 1
        $x_1_11 = "tmrStopKill" ascii //weight: 1
        $x_1_12 = "cmdConnect" ascii //weight: 1
        $x_1_13 = "cmdDownload" ascii //weight: 1
        $x_1_14 = "KillTimer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hupigon_RI_2147836447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hupigon.RI!MTB"
        threat_id = "2147836447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 1a 99 59 f7 f9 80 c2 61 88 14 1f 43 3b de 7c ea}  //weight: 1, accuracy: High
        $x_1_2 = {b9 e8 03 00 00 f7 f1 33 d2 b9 80 51 01 00 be 10 0e 00 00 6a 3c 5f 2b 44 24 0c f7 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hupigon_AA_2147890011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hupigon.AA!MTB"
        threat_id = "2147890011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 8b 84 24 ?? 01 00 00 73 07 8d 84 24 ?? 01 00 00 8a ?? 38 8b 44 24 ?? 30 ?? 06 8b ?? 24 ?? 83 c6 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hupigon_AB_2147890012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hupigon.AB!MTB"
        threat_id = "2147890012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 8a 88 ?? ?? ?? ?? 88 4d ef 0f b6 45 ef 83 f0 47 88 45 ef 0f b6 45 ef f7 d8 88 45 ef 0f b6 45 ef 2d e8 00 00 00 88 45 ef 0f b6 45 ef f7 d8}  //weight: 1, accuracy: Low
        $x_1_2 = {88 45 ef 0f b6 45 ef 83 f0 6f 88 45 ef 8b 45 f8 8a 4d ef 88 88 ?? ?? ?? ?? e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Hupigon_NH_2147899139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hupigon.NH!MTB"
        threat_id = "2147899139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xinfd.com" ascii //weight: 1
        $x_1_2 = "bad_e9xc" ascii //weight: 1
        $x_1_3 = "ShellExecuteA" ascii //weight: 1
        $x_1_4 = "AspackDie!" ascii //weight: 1
        $x_1_5 = "TerminateProcess" ascii //weight: 1
        $x_1_6 = "CreateFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hupigon_AHU_2147956372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hupigon.AHU!MTB"
        threat_id = "2147956372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 46 64 68 68 aa 46 00 8b 46 30 50 e8 ?? ?? ?? ?? 89 46 68 68 70 aa 46 00 8b 46 30 50 e8 ?? ?? ?? ?? 89 46 6c 68 7c aa 46 00 8b 46 30 50 e8 ?? ?? ?? ?? 89 46 70 68 84 aa 46 00 8b 46 30 50 e8 ?? ?? ?? ?? 89 46 74 68}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 46 30 50 e8 ?? ?? ?? ?? 89 46 50 68 38 aa 46 00 8b 46 30 50 e8 ?? ?? ?? ?? 89 46 54 68 40 aa 46 00 8b 46 30 50 e8 ?? ?? ?? ?? 89 46 58 68 4c aa 46 00 8b 46 30 50 e8 ?? ?? ?? ?? 89 46 5c 68 54 aa 46 00 8b 46 30 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


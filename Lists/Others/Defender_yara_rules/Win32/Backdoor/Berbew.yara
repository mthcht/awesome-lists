rule Backdoor_Win32_Berbew_B_2147594707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Berbew.gen!B"
        threat_id = "2147594707"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Berbew"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {70 64 33 32 00 00 00 00 42 6c 61 63 6b 64 00 00 42 6c 61 63 6b 69 63 65 00 00 00 00 43 66 69 61}  //weight: 2, accuracy: High
        $x_2_2 = {57 66 69 6e 64 76 33 32 00 00 00 00 5a 6f 6e 65 61 6c 61 72 6d 00 00 00 6d 73 62 6c 61 73 74 00}  //weight: 2, accuracy: High
        $x_2_3 = {69 6f 5c 50 72 6f 67 72 61 6d 61 73 5c 49 6e 69 63 69 6f 5c 00 00 00 00 5c 57 49 4e 4d 45 5c 4d}  //weight: 2, accuracy: High
        $x_2_4 = {4e 49 43 4b 20 25 73 0a 55 53 45 52 20 25 73 20}  //weight: 2, accuracy: High
        $x_2_5 = {73 74 61 72 74 0d 0a 69 66 20 6e 6f 74 20 65 78 69 73 74 20 22 22 25 2a 22 22 20 67 6f 74 6f 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Berbew_M_2147813015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Berbew.M!MTB"
        threat_id = "2147813015"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Berbew"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 85 d0 fe ff ff 89 c3 31 d8 89 c3 29 d8 89 c3 f7 e3 89 85 cc fe ff ff}  //weight: 10, accuracy: High
        $x_10_2 = {b8 46 3c 00 00 f7 e3 89 85 d8 fe ff ff 89 c3 f7 e3 89 85 d4 fe ff ff 89 c3 81 c3 41 7d 00 00 68 04 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Berbew_GZ_2147814054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Berbew.GZ!MTB"
        threat_id = "2147814054"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Berbew"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c3 31 d8 89 c3 01 d8 89 c3 b8 ?? ?? ?? ?? f7 e3 89 85 ?? ?? ?? ?? 89 c3 81 f3 ?? ?? ?? ?? 89 d8 29 d8 89 c3 b8 ?? ?? ?? ?? f7 e3 89 85 a4 fe ff ff 89 c3 31 c0 40 5f 5e 5b c9 c2 0c 00}  //weight: 10, accuracy: Low
        $x_1_2 = "OpenMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Berbew_GGT_2147896100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Berbew.GGT!MTB"
        threat_id = "2147896100"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Berbew"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 85 e8 fe ff ff 09 c0 74 50 89 d8 31 d8 89 c3 b8 ?? ?? ?? ?? f7 e3 89 85 ?? ?? ?? ?? 89 c3 31 d8 89 c3}  //weight: 10, accuracy: Low
        $x_10_2 = {89 d8 01 d8 89 c3 81 eb ?? ?? ?? ?? 89 d8 31 d8 89 c3 81 c3 ?? ?? ?? ?? 31 c0 40 e9 e9}  //weight: 10, accuracy: Low
        $x_1_3 = "OpenMutex" ascii //weight: 1
        $x_1_4 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


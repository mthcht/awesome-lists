rule Backdoor_Win32_Warood_A_2147706600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Warood.A"
        threat_id = "2147706600"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Warood"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 f9 3f 74 39 80 f9 47 75 22 80 7c 3e 01 45 75 1b 80 7c 3e 02 54 75 14}  //weight: 1, accuracy: High
        $x_1_2 = {81 7c 3e 01 72 61 77 64 75 75 81 7c 3e 05 6f 6f 72 20 75 6b 83 c6 09}  //weight: 1, accuracy: High
        $x_1_3 = {81 3a 2f 6c 6f 67 0f 85 e0 00 00 00 81 7a 04 6f 2e 67 69 0f 85 d3 00 00 00 81 7a 08 66 3f 6d 3d}  //weight: 1, accuracy: High
        $x_1_4 = {3c 6c 74 04 3c 72 75 6e 8b 4d e0 8d 41 ff 3d fd ff 00 00 77 61}  //weight: 1, accuracy: High
        $x_1_5 = "dir=in action=allow protocol=UDP localport=%u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Warood_B_2147706602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Warood.B"
        threat_id = "2147706602"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Warood"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 31 8a 18 d2 e2 0a da 41 83 f9 08 88 18 7c ef}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 01 8a 18 32 da 88 18 40 4e 75 f3}  //weight: 1, accuracy: High
        $x_1_3 = "[-]NTTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Warood_C_2147706656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Warood.C"
        threat_id = "2147706656"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Warood"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 54 54 69 6d 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 70 6c 6f 61 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b cd 4f c1 e9 02 f3 a5 8b cd 6a 01 83 e1 03 6a 01 f3 a4 50 ff 15 ?? ?? ?? ?? 8b f0 8d 44 24 ?? 50 ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


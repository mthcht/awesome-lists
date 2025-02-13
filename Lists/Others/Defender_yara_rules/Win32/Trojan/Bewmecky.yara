rule Trojan_Win32_Bewmecky_A_2147626860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bewmecky.A"
        threat_id = "2147626860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bewmecky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7c 3b 83 7d 08 05 75 35 8b 75 0c 8b de 83 3e 00 74 2b 03 36 8b 4e 44}  //weight: 1, accuracy: High
        $x_1_2 = {6a 10 ff 15 ?? ?? ?? ?? 66 85 c0 79 0b 83 c6 9f 83 fe 19 77 03 80 c3 e0}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f8 8a 04 30 fe c0 3c 26 88 06 75 03 c6 06 24 ff 75 08 ?? 46 e8 ?? ?? ?? ?? 3b ?? 59 72 e0}  //weight: 1, accuracy: Low
        $x_1_4 = {75 f2 eb 2a 8b 3d ?? ?? ?? ?? 8d 45 08 50 6a 40 6a 04 56 ff d7 50 ff 15 ?? ?? ?? ?? 6a 00 6a 04 8d 45 0c 50 56 ff d7 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


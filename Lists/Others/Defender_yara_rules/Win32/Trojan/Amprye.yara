rule Trojan_Win32_Amprye_A_2147641427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amprye.A"
        threat_id = "2147641427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amprye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 75 23 80 7c ?? ?? 04 75 1c 80 7c ?? ?? 83 75 15 80 7c ?? ?? 04}  //weight: 1, accuracy: Low
        $x_1_2 = {83 b8 84 00 00 00 14 73}  //weight: 1, accuracy: High
        $x_1_3 = {8b 07 3d 50 4f 53 54 74 ?? 3d 47 45 54 20 74}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 46 28 83 c4 18 85 c0 b3 01 88 5d f3 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {45 4e 44 49 4e 54 45 43 45 50 54 56 41 52 49 41 42 4c 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


rule Trojan_Win32_Higspoo_A_2147709382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Higspoo.A"
        threat_id = "2147709382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Higspoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6d 6d 61 6e 64 00 68 6f 73 74 00 70 61 74 68 00 44 4f 57 4e 4c 4f 41 44 00 53 45 54 55 50 00 44 45 53 54 52 4f 59 00 72 65 73 75 6c 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {7b 22 75 75 69 64 22 3a 22 ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 2c 22 68 6f 73 74 22 3a 22 [0-20] 22 2c 22 70 61 74 68 22 3a 22 [0-16] 22 2c 22 70 6f 72 74 22 3a 05 00 7d}  //weight: 1, accuracy: Low
        $x_1_3 = {75 75 69 64 00 68 6f 73 74 00 70 61 74 68 00 70 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 48 67 67 64 79 54 54 4a 4c 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 53 70 6f 6f 6c 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


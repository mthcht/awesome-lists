rule Backdoor_Win32_Achens_A_2147712089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Achens.A!bit"
        threat_id = "2147712089"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Achens"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 2f c6 85 ?? ?? ff ff 54 c6 85 ?? ?? ff ff 41 c6 85 ?? ?? ff ff 53 c6 85 ?? ?? ff ff 4b c6 85 ?? ?? ff ff 4b c6 85 ?? ?? ff ff 49 c6 85 ?? ?? ff ff 4c c6 85 ?? ?? ff ff 4c c6 85 ?? ?? ff ff 20 c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 0d c6 85 ?? ?? ff ff 0a c6 85 ?? ?? ff ff 00 c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 53 c6 85 ?? ?? ff ff 48 c6 85 ?? ?? ff ff 55 c6 85 ?? ?? ff ff 54 c6 85 ?? ?? ff ff 44 c6 85 ?? ?? ff ff 4f c6 85 ?? ?? ff ff 57 c6 85 ?? ?? ff ff 4e c6 85 ?? ?? ff ff 0d c6 85 ?? ?? ff ff 0a}  //weight: 1, accuracy: Low
        $x_2_2 = {fe c1 81 e1 ff 00 00 00 8a 44 0c ?? 8a d8 02 da 81 e3 ff 00 00 00 8b d3 8a 5c 14 ?? 88 5c 0c ?? 88 44 14 ?? 8a 5c 0c ?? 02 d8 81 e3 ff 00 00 00 8a 44 1c ?? 8a 1c 37 32 c3 88 06 46 4d 75 c1}  //weight: 2, accuracy: Low
        $x_1_3 = {c6 85 00 ff ff ff 77 c6 85 01 ff ff ff 77 c6 85 02 ff ff ff 77 c6 85 03 ff ff ff 2e c6 85 04 ff ff ff 6e c6 85 05 ff ff ff 65 c6 85 06 ff ff ff 74 c6 85 07 ff ff ff 77 c6 85 08 ff ff ff 6f c6 85 09 ff ff ff 72 c6 85 0a ff ff ff 6b c6 85 0b ff ff ff 2e c6 85 0c ff ff ff 73 c6 85 0d ff ff ff 65 c6 85 0e ff ff ff 72 c6 85 0f ff ff ff 76 c6 85 10 ff ff ff 65 c6 85 11 ff ff ff 75 c6 85 12 ff ff ff 73 c6 85 13 ff ff ff 65 c6 85 14 ff ff ff 72 c6 85 15 ff ff ff 2e c6 85 16 ff ff ff 63 c6 85 17 ff ff ff 6f c6 85 18 ff ff ff 6d c6 85 19 ff ff ff 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d c6 84 24 ?? 00 00 00 6f c6 84 24 ?? 00 00 00 7a c6 84 24 ?? 00 00 00 69 c6 84 24 ?? 00 00 00 6c c6 84 24 ?? 00 00 00 6c c6 84 24 ?? 00 00 00 61 c6 84 24 ?? 00 00 00 2f c6 84 24 ?? 00 00 00 35 c6 84 24 ?? 00 00 00 2e c6 84 24 ?? 00 00 00 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


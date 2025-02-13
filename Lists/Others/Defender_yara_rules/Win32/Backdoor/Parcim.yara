rule Backdoor_Win32_Parcim_A_2147681819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Parcim.A"
        threat_id = "2147681819"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Parcim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c9 83 fd 02 0f 9f c1 51 50 e8 ?? ?? ?? ?? 83 c4 08 5d 68 b8 0b 00 00 ff 15 ?? ?? ?? ?? eb f3}  //weight: 2, accuracy: Low
        $x_2_2 = {7e 14 8b 4c 24 04 53 8a 1c 08 80 f3 87 88 1c 08 40 3b c2 7c f2}  //weight: 2, accuracy: High
        $x_2_3 = {68 50 c3 00 00 50 ff 15 ?? ?? ?? ?? 3d 02 01 00 00 75 3c}  //weight: 2, accuracy: Low
        $x_1_4 = {53 76 63 48 6f 73 74 44 4c 4c 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 70 61 72 00 00 00 00 6d 5f}  //weight: 1, accuracy: High
        $x_1_6 = {6d 5f 4d 61 69 6e 55 72 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = {6d 5f 42 61 63 6b 55 72 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = {6d 5f 44 6c 6c 4e 61 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


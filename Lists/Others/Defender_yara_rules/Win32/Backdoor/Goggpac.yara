rule Backdoor_Win32_Goggpac_2147627073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Goggpac"
        threat_id = "2147627073"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Goggpac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 3c 04 00 00 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 00 57 68 1e 04 00 00}  //weight: 3, accuracy: Low
        $x_1_2 = {76 33 66 bf 01 00 0f b7 c7 8b 55 fc 0f b6 44 02 ff 66 89 45 fa 8d 45 f4 66 8b 55 fa 66 83 f2}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 68 00 30 00 00 8b 45 e4 8b 40 50 50 8b 45 e4 8b 40 34 50 8b 45 d0 50 e8}  //weight: 1, accuracy: High
        $x_1_4 = {8b d7 66 81 f2 ?? ?? 88 50 01 c6 00 01 8d 95}  //weight: 1, accuracy: Low
        $x_1_5 = {79 74 69 72 75 63 65 53 20 74 65 6e 72 65 74 6e 49 20 74 66 6f 73 67 6e 69 4b 00}  //weight: 1, accuracy: High
        $x_1_6 = {65 78 65 2e 65 63 69 76 72 65 73 65 72 61 77 6d 76 00}  //weight: 1, accuracy: High
        $x_1_7 = {63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 00}  //weight: 1, accuracy: High
        $x_1_8 = "./DRAT/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


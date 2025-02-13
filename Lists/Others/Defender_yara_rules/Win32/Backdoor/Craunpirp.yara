rule Backdoor_Win32_Craunpirp_A_2147696170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Craunpirp.A"
        threat_id = "2147696170"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Craunpirp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {be a7 c6 67 4e 85 ff 74 1c 53 8b 5d 08 0f b6 0b 8b d6 c1 e2 05 8b c6 c1 e8 02 03 d0 03 d1 33 f2 43 4f 75 e9}  //weight: 2, accuracy: High
        $x_2_2 = {68 0c 00 00 08 50 50 50 ff 75 10 ff 75 08 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? a1 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 07 00 01 00}  //weight: 2, accuracy: Low
        $x_1_3 = {4f 00 4c 00 4c 00 59 00 44 00 42 00 47 00 2e 00 45 00 58 00 45 00 00 00 00 00 00 00 6f 00 6c 00 6c 00 79 00 64 00 62 00 67 00 2e 00 65 00 78 00 65 00 00 00 00 00 00 00 4f 00 6c 00 6c 00 79 00 64 00 62 00 67 00 2e 00 65 00 78 00 65 00 00 00 00 00 00 00 4f 00 6c 00 6c 00 79 00 44 00 62 00 67 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b f1 8a 04 95 ?? ?? ?? ?? 30 06 46 42 33 c0 83 fa 08 0f 4d d0 38 06 75 e9}  //weight: 1, accuracy: Low
        $x_3_5 = {00 52 54 7c 00 46 54 7c 00 56 49 7c 00 56 56 7c 00 49 50 7c 00 43 50 7c 00 52 50 7c 00 52 41 7c 00 55 4e 7c 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}


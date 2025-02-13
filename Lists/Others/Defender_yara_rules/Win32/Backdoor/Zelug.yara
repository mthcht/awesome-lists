rule Backdoor_Win32_Zelug_A_2147663266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zelug.A"
        threat_id = "2147663266"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zelug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 14 3c 42 75 11 8d 4c 24 11 51 e8 ?? ?? ?? ?? 83 c4 04 89 44 24 30 8b 16 6a 03 8b ce ff 12}  //weight: 1, accuracy: Low
        $x_1_2 = {50 33 c0 8a 87 99 01 00 00 33 c9 8a 8f 98 01 00 00 33 d2 8a 97 97 01 00 00 50 51 33 c0 8a 87 96 01 00 00 52}  //weight: 1, accuracy: High
        $x_1_3 = {8a 06 83 c4 14 3c 42 75}  //weight: 1, accuracy: High
        $x_2_4 = "zhugeliannu" ascii //weight: 2
        $x_1_5 = {25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 34 58 00}  //weight: 1, accuracy: High
        $x_1_6 = {63 6d 64 63 6f 6d 6d 61 6e 64 3a 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zelug_B_2147708236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zelug.B"
        threat_id = "2147708236"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zelug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 33 c0 8a 87 99 01 00 00 33 c9 8a 8f 98 01 00 00 33 d2 8a 97 97 01 00 00 50 51 33 c0 8a 87 96 01 00 00 52}  //weight: 1, accuracy: High
        $x_2_2 = "zhugeliannu" ascii //weight: 2
        $x_1_3 = {25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 34 58 00}  //weight: 1, accuracy: High
        $x_1_4 = {70 6f 73 74 20 72 63 34 64 65 63 72 79 70 74 3a 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


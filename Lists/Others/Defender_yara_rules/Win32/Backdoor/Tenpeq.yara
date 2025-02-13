rule Backdoor_Win32_Tenpeq_A_2147614200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tenpeq.gen!A"
        threat_id = "2147614200"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tenpeq"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {89 83 68 00 10 00 6a 01 68 91 05 00 00 68 91 05 00 00 6a 00 8d 45 e0 50 e8 ?? ?? ff ff 85 c0 0f 84 ?? ?? 00 00 8b 45 e8 83 f8 1a 0f 87}  //weight: 4, accuracy: Low
        $x_4_2 = {eb 07 6a 0a e8 ?? ?? ?? ?? 6a 14 6a 00 68 92 05 00 00}  //weight: 4, accuracy: Low
        $x_3_3 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 4d 00 50 00 45 00 47 00 2d 00 34 00 20 00 56 00 69 00 64 00 65 00 6f 00 20 00 43 00 6f 00 64 00 65 00 63 00 00 00}  //weight: 3, accuracy: High
        $x_3_4 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 6d 00 70 00 67 00 34 00 63 00 33 00 32 00 00 00}  //weight: 3, accuracy: High
        $x_9_5 = {00 53 4f 46 54 57 41 52 45 5c 51 51 5c 51 51 4e 45 54 50 45 54 00}  //weight: 9, accuracy: High
        $x_2_6 = {00 4e 65 74 50 65 74 4e 61 6d 65 00}  //weight: 2, accuracy: High
        $x_5_7 = {00 4d 61 73 74 65 72 44 4e 53 45 00}  //weight: 5, accuracy: High
        $x_2_8 = {6e 6f 74 20 49 73 53 75 63 65 73 73 00}  //weight: 2, accuracy: High
        $x_5_9 = {00 52 55 73 65 72 32 30 30 39 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_9_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_9_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_9_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_9_*) and 1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_9_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Tenpeq_D_2147693092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tenpeq.D"
        threat_id = "2147693092"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tenpeq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AO1LE1J2K" ascii //weight: 1
        $x_1_2 = "SW50ZXJuZXRDb25uZWN0QQ==" ascii //weight: 1
        $x_1_3 = {68 65 6c 6c 6f 00 44 30 44 36 35 30 39 46 46}  //weight: 1, accuracy: High
        $x_1_4 = {74 0d 68 06 00 00 00 e8 ?? ?? ?? ?? 83 c4 04 89 45 f8 68 01 03 00 80 6a 00 ff 75 f8 68 01 00 00 00 bb 0c 09 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {eb 91 8b 0b 83 c3 04 33 c0 85 c9 74 0d 8b 03 83 c3 04 49 74 05 0f af 03 eb f5}  //weight: 1, accuracy: High
        $x_1_6 = {38 31 46 38 43 34 37 43 35 43 38 42 39 39 34 44 00}  //weight: 1, accuracy: High
        $x_1_7 = {68 01 03 00 80 6a 00 ff 75 f8 68 01 00 00 00 bb 0c 09 00 00 e8 ?? ?? ?? ?? 83 c4 10 89 45 ?? 8b 45 ?? 50 8b 1d ?? ?? ?? ?? 85 db 74 09 53 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


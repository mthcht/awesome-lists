rule Trojan_Win32_Ontonphu_A_2147651925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ontonphu.A"
        threat_id = "2147651925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ontonphu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "..:::Free_Software:::.." ascii //weight: 1
        $x_1_2 = {48 54 54 50 53 3a 2f 2f 00}  //weight: 1, accuracy: High
        $x_1_3 = "memberlist.php?mode=viewprofile&u=" ascii //weight: 1
        $x_1_4 = "WebMoney" wide //weight: 1
        $x_1_5 = {50 8b 13 8b 0f b8 02 00 00 80 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Ontonphu_B_2147652639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ontonphu.B"
        threat_id = "2147652639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ontonphu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "User-Agent: YZF" ascii //weight: 1
        $x_1_2 = {76 69 65 77 66 6f 72 75 6d 2e 70 68 70 3f 66 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6d 65 6d 62 65 72 6c 69 73 74 2e 70 68 70 3f 6d 6f 64 65 3d 76 69 65 77 70 72 6f 66 69 6c 65 26 75 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 76 69 65 77 74 6f 70 69 63 2e 70 68 70 3f 74 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 65 6d 62 65 72 6c 69 73 74 2e 70 68 70 3f 6c 74 72 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 61 6c 65 6e 64 61 72 2e 70 68 70 3f 6d 6f 6e 74 68 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 76 62 75 6c 6c 65 74 69 6e 66 6c 6f 6f 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 6f 6e 74 63 70 66 6c 6f 6f 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 6f 6e 75 64 70 66 6c 6f 6f 64}  //weight: 1, accuracy: Low
        $x_10_5 = {59 5a 46 ff ff ff ff ?? ?? ?? ?? 73 68 6f 77 74 68 72 65 61 64 2e 70 68 70 3f 70 3d 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ontonphu_C_2147654227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ontonphu.C"
        threat_id = "2147654227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ontonphu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {bb 01 00 00 00 8b 45 fc 0f b6 44 18 ff 2b 45 f8 2b c3 33 45 f8 89 45 f4 8d 45 f0 8a 55 f4 e8}  //weight: 4, accuracy: High
        $x_2_2 = {63 85 80 87 8f 9f 98 4b 4d 6c}  //weight: 2, accuracy: High
        $x_2_3 = {51 85 96 99 95 9e 99 97 98 a4 00}  //weight: 2, accuracy: High
        $x_2_4 = {51 85 96 99 95 8c 96 8c 93 00}  //weight: 2, accuracy: High
        $x_2_5 = {78 9b 8d 6d 88 9f 8b 78 9e 9b a4 81 00}  //weight: 2, accuracy: High
        $x_2_6 = {94 91 93 94 9e 99 91 00}  //weight: 2, accuracy: High
        $x_2_7 = {64 90 9c 96 97 7f 85 a1 9c 93 95 a5 82 00}  //weight: 2, accuracy: High
        $x_2_8 = {6e 95 94 8a 78 8a a0 9d 93 a3 83 99 9f a7 00}  //weight: 2, accuracy: High
        $x_2_9 = {6a 85 9c 88 56 7b 9e a1 99 94 47 62 6a 6a 87 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ontonphu_D_2147660408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ontonphu.D"
        threat_id = "2147660408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ontonphu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 0f b6 44 18 ff 2b 45 f8 2b c3 33 45 f8 89 45 f4 8d 45 f0 8a 55 f4 e8 ?? ?? ?? ?? 8b 55 f0 8b c7 e8 ?? ?? ?? ?? 43 4e 75 d4 33 c0}  //weight: 2, accuracy: Low
        $x_2_2 = {68 20 02 00 00 6a 20 6a 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 1e 4b 85 db 7c ?? 43 33 ff 8b 44 fe 04}  //weight: 2, accuracy: Low
        $x_1_3 = "/gsxr/cmd.php" ascii //weight: 1
        $x_1_4 = {2f 63 6d 64 2e 70 68 70 [0-128] 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}


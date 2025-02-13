rule TrojanDropper_Win32_Machime_A_2147627117_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Machime.A"
        threat_id = "2147627117"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Machime"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 6d 69 6d 61 63 68 69 6e 65 32 2e 64 6c 6c 00 45 58 45 00 5c 69 6d 65 5c 00 00 00 2e 4e 45 54 20 52 75 6e 74 69 6d 65 20 4f 70 74 69 6d 69 7a 61 74 69 6f 6e 20 53 65 72 76 69 63 65 20 76 32 2e 30 38 36 35 32 31 2e 42 61 63 6b 55 70 5f 58 38 36}  //weight: 1, accuracy: High
        $x_1_2 = {3a 73 74 61 72 74 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 73 74 61 72 74 0d 0a 64 65 6c 20 25 25 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Machime_B_2147651810_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Machime.B"
        threat_id = "2147651810"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Machime"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 00 72 00 72 00 6f 00 72 00 2d 00 47 00 65 00 74 00 41 00 64 00 61 00 70 00 74 00 65 00 72 00 49 00 6e 00 66 00 6f 00 4c 00 69 00 73 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 00 73 00 2e 00 75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 25 00 64 00 2e 00 74 00 6d 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 00 70 00 6f 00 72 00 74 00 2e 00 [0-12] 2e 00 6b 00 72 00}  //weight: 1, accuracy: Low
        $x_1_4 = "ETag: \"c0c07192bcc1c81:d9f\"" ascii //weight: 1
        $x_1_5 = {81 f9 00 04 00 00 73 0b df 6c 24 04 b8 ?? ?? ?? ?? eb ?? ?? ?? 7f 3a 7c 08 81 f9 00 00 10 00 73 11 df 6c 24 04}  //weight: 1, accuracy: Low
        $x_1_6 = "<%10[^|]|%250[^:]:%u|%100[^|]|%10[^>]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


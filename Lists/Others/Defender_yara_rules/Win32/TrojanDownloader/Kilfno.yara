rule TrojanDownloader_Win32_Kilfno_A_2147620354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kilfno.A"
        threat_id = "2147620354"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilfno"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 63 20 64 65 6c 65 74 65 20 52 61 76 54 61 73 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 44 32 01 8a 0c 32 04 06 80 e9 08 24 0f 8b fe c0 e1 04 02 c1}  //weight: 1, accuracy: High
        $x_1_3 = {74 4d 6a 00 6a 00 6a 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Kilfno_C_2147627597_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kilfno.C"
        threat_id = "2147627597"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilfno"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {10 00 10 32 d1 88 ?? ?? 10 00 10 40 3d ?? ?? ?? ?? 7c ea}  //weight: 2, accuracy: Low
        $x_1_2 = {64 a1 30 00 00 00 40 40 8b 00 25 ff 00 00 00 85 c0 75 02 eb 04 b0 01 eb 02}  //weight: 1, accuracy: High
        $x_1_3 = {68 4b e1 22 00 50 ff 15 ?? ?? ?? ?? 85 c0 74 10}  //weight: 1, accuracy: Low
        $x_1_4 = {48 75 1c 72 03 73 01 e8 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


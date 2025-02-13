rule TrojanDownloader_Win32_Smawis_A_2147678932_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Smawis.A"
        threat_id = "2147678932"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Smawis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 77 00 73 00 2e 00 70 00 68 00 70 00 3f 00 78 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 86 96 01 00 00 33 c9 8a 8e 95 01 00 00 33 d2 8a 96 94 01 00 00 50 51 52}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 00 ff d7 81 fe 09 04 00 00 74 ?? 81 fe ?? ?? 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Smawis_D_2147678934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Smawis.D"
        threat_id = "2147678934"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Smawis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 05 00 00 00 be ?? ?? ?? ?? 8d bc 24 ?? ?? ?? ?? 8b e8 f3 a5 b9 7d 00 00 00 33 c0 8d bc 24 ?? ?? ?? ?? 33 d2 f3 ab}  //weight: 2, accuracy: Low
        $x_2_2 = {81 fe 09 0c 00 00 74 0c 81 fe 09 08 00 00 0f 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d ?? 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? ?? 8d ?? 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? ?? ff d3}  //weight: 2, accuracy: Low
        $x_2_3 = {77 00 73 00 2e 00 70 00 68 00 70 00 3f 00 78 00 3d 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {20 3e 3e 20 4e 55 4c 00 2f 63 20 64 65 6c 20 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 00 73 00 6d 00 6f 00 63 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


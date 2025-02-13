rule TrojanDownloader_Win32_Talalpek_A_2147712209_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Talalpek.A"
        threat_id = "2147712209"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Talalpek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 0d 6a 05 68 df 07 00 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 85 c0 74 0a c7 05 ?? ?? ?? 00 02 00 00 00 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {53 57 68 00 00 10 00 ff 15 ?? ?? 40 00 8b f0 85 f6 75 04 33 c0 eb ?? 68 10 27 00 00 56 ff 15}  //weight: 2, accuracy: Low
        $x_2_3 = {68 20 bf 02 00 50 ff 15 ?? ?? 40 00 33 f6 85 c0 74 ?? 56 ff 35 ?? ?? ?? 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_4 = {51 0f 57 c0 66 0f 13 45 ?? 6a 33 e8 00 00 00 00}  //weight: 2, accuracy: Low
        $x_2_5 = {54 8f 45 f8 e8 00 00 00 00 c7 44 24 04 23 00 00 00 83 04 24 0d cb}  //weight: 2, accuracy: High
        $x_1_6 = {0f b6 c2 03 c8 0f b6 c1 8b 4d f8 8a 84 05 ?? ?? ff ff 30 04 0f 47 3b 7d fc 72}  //weight: 1, accuracy: Low
        $x_1_7 = {5f 58 56 61 08 ff 34 ec d8 d4 ce 5a 6a 8a 7e 55 3a 41 66 e2 93 31 40 b3 5a 32 06 1b a4 8d ba ef}  //weight: 1, accuracy: High
        $x_1_8 = "\\5ed49bcf-286c-44b2-96af-6b8b567d3035" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Talalpek_B_2147716651_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Talalpek.B!bit"
        threat_id = "2147716651"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Talalpek"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 fc ff 35 ?? ?? ?? 10 ff 75 ?? ff 75 f4 ff 35 ?? ?? ?? 10 8f 05 ?? ?? ?? 10 ff 15 ?? ?? ?? 10 89 45 f0 8b 45 f0 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d ec 03 4d e4 8b 55 f4 03 55 e4 8a 02 88 01 c7 45 ?? ?? ?? 00 00 8b 4d f8 83 c1 01 89 4d f8 eb be}  //weight: 1, accuracy: Low
        $x_2_3 = {8b 55 f8 8b 02 33 85 ?? ?? ?? ff 8b 4d f8 89 01 8b e5 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


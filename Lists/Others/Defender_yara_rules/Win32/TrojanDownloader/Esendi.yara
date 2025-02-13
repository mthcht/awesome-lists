rule TrojanDownloader_Win32_Esendi_B_2147730224_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Esendi.B"
        threat_id = "2147730224"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Esendi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 e2 ff ff ff 7f 33 94 84 d8 09 00 00 8b ca 80 e1 01 0f b6 c9 f7 d9 1b c9 d1 ea 81 e1 df b0 08 99 33 8c 84 0c 10 00 00 33 ca 89 4c 84 18 40 3d e3 00 00 00 7c bc 3d 6f 02 00 00 7d 47 0f 1f 00}  //weight: 10, accuracy: High
        $x_10_2 = {81 e2 ff ff ff 7f 33 94 84 d8 09 00 00 8b ca 80 e1 01 0f b6 c9 f7 d9 1b c9 d1 ea 81 e1 df b0 08 99 33 8c 84 8c fc ff ff 33 ca 89 4c 84 18 40 3d 6f 02 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {8d 14 85 00 00 00 00 8b 8c 14 d8 09 00 00 33 4c 24 18 81 e1 ff ff ff 7f 33 8c 14 d8 09 00 00 8b c1 24 01 0f b6 c0 f7 d8 1b c0 d1 e9 25 df b0 08 99 33 c1 33 84 24 48 06 00 00 33 f6 89 44 14 18 89 74 24 14}  //weight: 10, accuracy: High
        $x_10_4 = {6b 4d 08 0c 83 ca ff 81 7d 08 55 55 55 15 0f 47 ca 51}  //weight: 10, accuracy: High
        $x_10_5 = {33 ff b8 c5 9d 1c 81 8b d5 8d 4d ?? 3b cd 1b db 83 e3 fc 83 c3 04 3b e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Esendi_C_2147730314_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Esendi.C"
        threat_id = "2147730314"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Esendi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {40 85 c9 74 21 8b 54 24 04 66 66 66 0f 1f 84 00 00 00 00 00 01 91 ?? ?? ?? ?? 8b 0c 85 ?? ?? ?? ?? 40 85 c9 75}  //weight: 20, accuracy: Low
        $x_20_2 = {50 01 00 20 00 00 00 00 60 01 00 00 70 00 00 02 00 00 00}  //weight: 20, accuracy: High
        $x_20_3 = {50 01 00 40 00 00 00 00 60 01 00 00 70 00 00 04 00 00 00}  //weight: 20, accuracy: High
        $x_20_4 = {05 00 20 00 00 00 00 10 05 00 00 30 01 00 02 00 00 00}  //weight: 20, accuracy: High
        $x_10_5 = {8b c2 8d 7f 04 c1 e8 1e 33 c2 69 d0 65 89 07 6c 03 d6 46 89 57 fc 81 fe 70 02 00 00}  //weight: 10, accuracy: High
        $x_10_6 = {81 e1 ff ff ff 7f 33 c8 8b c1 24 01 0f b6 c0 f7 d8 1b c0 d1 e9 25 df b0 08 99}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 1 of ($x_10_*))) or
            ((3 of ($x_20_*))) or
            (all of ($x*))
        )
}


rule TrojanDownloader_Win32_Kolilks_A_2147616969_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kolilks.A"
        threat_id = "2147616969"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kolilks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 6a 2b 99 59 f7 f9 83 c2 30 83 fa 39 7e 05 83 fa 41 7c eb}  //weight: 1, accuracy: High
        $x_1_2 = {68 ff 7f 00 00 6a 01 68 ?? ?? ?? ?? ff 15 03 00 74 1d (56|57)}  //weight: 1, accuracy: Low
        $x_1_3 = {3d a8 08 00 00 74 ?? 3d e8 02 00 00 75}  //weight: 1, accuracy: Low
        $x_10_4 = {6a 7c 8d 4d 08 e8 ?? ?? ?? ?? 83 c3 04 81 fb ?? ?? ?? ?? 8b ?? 7c b7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Kolilks_B_2147626749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kolilks.B"
        threat_id = "2147626749"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kolilks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 74 5a 33 c0 66 c7 45 d4 68 00 66 89 55 d6 66 89 55 d8 66 c7 45 da 70 00 66 c7 45 dc 3a 00 66 c7 45 de 2f 00 66 c7 45 e0 2f 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 7c 8d 4d ?? 89 5d ?? e8 ?? ?? ?? ?? 83 c6 04 ff 4d f0 8b d8 75 b6}  //weight: 1, accuracy: Low
        $x_1_3 = {68 bb 01 00 00 50 8d 4d ?? e8 ?? ?? ?? ?? 8b d8 f7 db 1a db 8d 4d fc fe c3 e8 ?? ?? ?? ?? 84 db 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Kolilks_D_2147631481_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kolilks.D"
        threat_id = "2147631481"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kolilks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 68 00 40 ff ff 53 ff 15 ?? ?? ?? ?? 53 68 00 c0 00 00 bf ?? ?? ?? ?? 6a 01 57 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 05 ff 75 f8 ff 15 ?? ?? ?? ?? 3d 5e 04 00 00 90 ff 15 ?? ?? ?? ?? 6a 04 6a 00 ff 75 f8 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Kolilks_E_2147692729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kolilks.E"
        threat_id = "2147692729"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kolilks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "/kills.txt?t" ascii //weight: 4
        $x_2_2 = {83 c9 ff 8b f7 8d 54 24 0c 8b fa f2 ae 8b cb c1 e9 02 4f f3 a5 8b cb 83 e1 03 f3 a4}  //weight: 2, accuracy: High
        $x_2_3 = {b9 1a 00 00 00 f7 f9 80 c2 41 88 54 34 0c 46 3b f7 7c ea}  //weight: 2, accuracy: High
        $x_1_4 = ".lmok123.com/" ascii //weight: 1
        $x_1_5 = "baiduasp.web194.dns911.cn/" ascii //weight: 1
        $x_1_6 = "/122.224.9.151/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}


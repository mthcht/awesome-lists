rule TrojanDownloader_Win32_Hoptto_A_2147664849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hoptto.A"
        threat_id = "2147664849"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hoptto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 60 ea 00 00 e8 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? e9 ?? ?? ?? ?? 68 00 00 00 00 e8 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 08 01 00 00 80 ba ?? ?? ?? ?? 8d 4c 24 0c e8 ?? ?? ?? ?? 8d 44 24 10 50 8b 44 24 10 50 ff 74 24 10 e8 ?? ?? ?? ?? ff 74 24 04}  //weight: 1, accuracy: Low
        $x_1_3 = {89 c3 81 c3 10 27 00 00 89 1c 24 ff 35 ?? ?? ?? ?? 68 00 00 00 00 68 00 00 00 00 [0-128] 8b 6c 24 20 ff 75 00 68 00 00 00 00 8b 15 ?? ?? ?? 00 01 54 24 08 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {70 75 72 65 6e 65 74 2e 68 6f 70 74 6f 2e 6f 72 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Hoptto_B_2147672244_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hoptto.B"
        threat_id = "2147672244"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hoptto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "420"
        strings_accuracy = "High"
    strings:
        $x_200_1 = "142.0.36.34/" ascii //weight: 200
        $x_100_2 = "miner.dll" ascii //weight: 100
        $x_100_3 = "usft_ext.txt" ascii //weight: 100
        $x_200_4 = {85 ff 7e 4e bb 01 00 00 00 8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8}  //weight: 200, accuracy: High
        $x_10_5 = "/main.txt" ascii //weight: 10
        $x_10_6 = "phatk.txt" ascii //weight: 10
        $x_100_7 = "/37.221.160.56/" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_200_*) and 2 of ($x_100_*) and 2 of ($x_10_*))) or
            ((1 of ($x_200_*) and 3 of ($x_100_*))) or
            ((2 of ($x_200_*) and 2 of ($x_10_*))) or
            ((2 of ($x_200_*) and 1 of ($x_100_*))) or
            (all of ($x*))
        )
}


rule TrojanDownloader_Win32_Gladgerown_A_2147639100_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gladgerown.A"
        threat_id = "2147639100"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gladgerown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 09 8b 55 fc 83 ea 04 89 55 fc 8b 45 fc 3b 45 08 72 12 8b 4d fc 8b 11 81 f2 71 01 10 17 8b 45 fc 89 10 eb dd}  //weight: 1, accuracy: High
        $x_1_2 = {6a 10 8b 55 ?? 83 c2 38 52 8b 45 ?? 8b 48 30 51 e8 ?? ?? 00 00 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Gladgerown_B_2147647266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gladgerown.B"
        threat_id = "2147647266"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gladgerown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 09 8b 55 ?? 83 ea 04 89 55 ?? 8b 45 ?? 3b 45 ?? 72 12 8b 4d ?? 8b 11 81 f2 ?? ?? ?? ?? 8b 45 ?? 89 10 eb dd}  //weight: 2, accuracy: Low
        $x_1_2 = {33 d0 8b 45 ?? 03 45 ?? 88 10 8b 4d ?? 83 c1 01 89 4d ?? 8b 55 ?? 3b 55 ?? 75 07}  //weight: 1, accuracy: Low
        $x_1_3 = {25 30 38 78 00 [0-7] 25 73 5f 25 78 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


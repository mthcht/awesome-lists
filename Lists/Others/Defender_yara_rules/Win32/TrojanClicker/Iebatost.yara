rule TrojanClicker_Win32_Iebatost_A_2147685731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Iebatost.A"
        threat_id = "2147685731"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Iebatost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "105"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\BlockedPopup\\.current" ascii //weight: 1
        $x_1_2 = "\\Navigating\\.current" ascii //weight: 1
        $x_1_3 = "\\SecurityBand\\.current" ascii //weight: 1
        $x_2_4 = "ie.getitclear.com" ascii //weight: 2
        $x_3_5 = "f40004Zxx" ascii //weight: 3
        $x_3_6 = "r0000k" ascii //weight: 3
        $x_3_7 = "vod00" ascii //weight: 3
        $x_3_8 = "exxxi" ascii //weight: 3
        $x_3_9 = "f40004" ascii //weight: 3
        $x_3_10 = {68 60 ea 00 00 ff d3 [0-16] ff d6 85 c0 74}  //weight: 3, accuracy: Low
        $x_100_11 = {89 44 24 10 6a 64 ff d5 6a 00 6a 09 ff d3 c1 e0 10 50 6a 09 68 00 01 00 00 56 ff d7 6a 00 6a 09 ff d3 c1 e0 10 50 6a 09 68 01 01 00 00 56 ff d7 8b 44 24 10 48 89 44 24 10 75 c9}  //weight: 100, accuracy: High
        $x_100_12 = {6a 64 ff 15 ?? ?? ?? ?? 6a 00 6a 09 ff d5 c1 e0 10 50 6a 09 68 00 01 00 00 57 ff d3 6a 00 6a 09 ff d5 c1 e0 10 50 6a 09 68 01 01 00 00 57 ff d3 83 ee 01 85 f6 7f c9}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_3_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}


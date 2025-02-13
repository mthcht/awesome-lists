rule TrojanDownloader_Win32_Korwelur_A_2147687790_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Korwelur.A"
        threat_id = "2147687790"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Korwelur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "5072837e7f443e39868186387f7382737f7382737d6f743872797c39856f817375833d7a777a" wide //weight: 4
        $x_4_2 = "w.tcmb.gov.tr/kurlar/today.htm" wide //weight: 4
        $x_2_3 = "wuactlyx.exe" wide //weight: 2
        $x_1_4 = "Heydex Exe\\" wide //weight: 1
        $x_1_5 = {3e 00 00 00 72 00 74 00 75 00 70 00 2e 00 68 00 6f 00 6d 00 65 00 70 00 61 00 67 00 65 00 5f 00 6f 00 76 00 65 00 72 00 72 00 69 00 64 00 65 00 2e 00 62 00 75 00 69 00 6c 00 64 00 49 00 44 00 22 00}  //weight: 1, accuracy: High
        $x_1_6 = "ms=1&id=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


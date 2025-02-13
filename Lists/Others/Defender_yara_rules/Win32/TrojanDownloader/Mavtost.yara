rule TrojanDownloader_Win32_Mavtost_A_2147710698_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mavtost.A"
        threat_id = "2147710698"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mavtost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {32 06 2a 45 74 fe c8 ff 45 74 88 04 0a 41 39 7d 74 72 e7}  //weight: 3, accuracy: High
        $x_3_2 = {32 c2 2a c1 fe c8 88 04 2e 41 46 3b cf 72 eb}  //weight: 3, accuracy: High
        $x_2_3 = {30 0c 30 8b 0d [0-4] 8a 49 02 0f b6 d9 40 81 ?? 24 6d 00 00 3b c3}  //weight: 2, accuracy: Low
        $x_2_4 = {30 0c 10 a1 [0-4] 8a 48 02 0f b6 c1 42 05 ?? 6d 00 00 3b d0}  //weight: 2, accuracy: Low
        $x_1_5 = "Krypton" ascii //weight: 1
        $x_1_6 = "masterhost122" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}


rule TrojanDownloader_Win32_PandoraBlade_A_2147813516_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PandoraBlade.A!dha"
        threat_id = "2147813516"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PandoraBlade"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 01 00 00 5d 0a 08 11 06 06 94 58 0c 08 20 00 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {20 00 01 00 00 8d ?? 00 00 01 13 ?? 20 00 01 00 00 8d ?? 00 00 01 13 ?? 03 8e 69 8d ?? 00 00 01}  //weight: 1, accuracy: Low
        $x_2_3 = {2f 00 73 00 74 00 6e 00 65 00 6d 00 68 00 63 00 61 00 74 00 74 00 61 00 2f 00 [0-64] 2f 00 2f 00 3a 00 73 00 70 00 74 00 74 00 68 00}  //weight: 2, accuracy: Low
        $x_1_4 = "- Kiss The Rain -" wide //weight: 1
        $x_1_5 = "exe.tneilC/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


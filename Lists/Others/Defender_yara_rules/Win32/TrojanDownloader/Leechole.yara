rule TrojanDownloader_Win32_Leechole_A_2147678581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Leechole.A"
        threat_id = "2147678581"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Leechole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 6e 74 2e 70 68 70 (00|3f)}  //weight: 10, accuracy: Low
        $x_10_2 = {67 65 74 2e 70 68 70 3f 65 3d [0-4] 26 74 63 3d [0-24] 26 75 69 64 3d}  //weight: 10, accuracy: Low
        $x_10_3 = {2e 65 78 65 00 2e 63 6e 74 00 75 69 64 00 73 7a 00 75 00 74 63 00}  //weight: 10, accuracy: High
        $x_1_4 = {26 72 64 3d 20 00 2e 65 78 65 (22|00) (63 6f 70|00)}  //weight: 1, accuracy: Low
        $x_1_5 = {63 6f 70 79 00 26 72 64 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}


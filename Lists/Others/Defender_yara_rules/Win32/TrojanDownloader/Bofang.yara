rule TrojanDownloader_Win32_Bofang_B_2147612114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bofang.B"
        threat_id = "2147612114"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bofang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 13 42 8b c6 8a 08 84 c9 74 0a 80 f1 ?? 88 08 40 fe ca 75 f0}  //weight: 2, accuracy: Low
        $x_2_2 = {50 6a 00 68 ?? ?? 40 00 8b 45 ?? 50 8b 00 ff 50 0c 85 c0 0f 85 ?? 01 00 00 83 7d ?? 00 0f 84 ?? 01 00 00 6a 00 8b 45 ?? 50 8b 00 ff 50 54}  //weight: 2, accuracy: Low
        $x_1_3 = "sipabot" ascii //weight: 1
        $x_1_4 = "kiwibot" ascii //weight: 1
        $x_1_5 = {5c 41 64 6f 62 65 [0-5] 5c 4d 61 6e 61 67 65 72 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_6 = "task.php?v=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule TrojanDownloader_Win32_Oderoor_A_2147611487_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Oderoor.gen!A"
        threat_id = "2147611487"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Oderoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 73 3f 72 75 6e 3d 31 00}  //weight: 10, accuracy: High
        $x_1_2 = {25 73 3f 64 3d 25 64 00 25 73 3f 69 3d 31 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 63 25 75 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 25 30 38 78 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_3_5 = {ab ab 6a 10 8d 45 ?? 50 53 ff 15 ?? ?? ?? ?? 85 c0 7d 04 33 c0 eb ?? ff 75 ?? 8d 85 ?? ?? ff ff ff 75 ?? 68}  //weight: 3, accuracy: Low
        $x_3_6 = {83 c0 0f eb 01 40 80 38 20 74 fa 8a 08 89 5c 24 ?? 3a cb 74 ?? 8b f0 8a c1 2c ?? 3c ?? 77}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}


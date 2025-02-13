rule TrojanDownloader_Win32_Tinyloader_A_2147707607_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tinyloader.A"
        threat_id = "2147707607"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinyloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 13 3d ac 04 00 00 73 08 83 c0 04 83 c3 04 eb e9 29 c3 31 c0 [0-15] 31 ?? 81 3b c3 c3 c3 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tinyloader_D_2147708890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tinyloader.D"
        threat_id = "2147708890"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinyloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 7c 03 ff c3 74 02 eb 18 8b 45 00 83 c0 0c ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {e8 08 00 00 00 63 6f 6e 6e 65 63 74 00 ff 75 48 ff 55 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


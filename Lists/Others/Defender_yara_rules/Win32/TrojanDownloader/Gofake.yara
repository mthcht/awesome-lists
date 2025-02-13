rule TrojanDownloader_Win32_Gofake_A_2147690056_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gofake.A"
        threat_id = "2147690056"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gofake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 45 f4 01 81 7d f4 e5 00 00 00 7e d6 83 7d ec 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 45 f4 01 81 7d f4 f8 20 00 00 7e d6 8b 45 e4 89 c2 8b 45 ec 8d 48 05}  //weight: 1, accuracy: High
        $x_1_3 = {c1 e9 1f 01 c8 d1 f8 03 45 08 0f b6 00 88 02 8b 45 f4 83 c0 01 89 c2 03 55 f0 8b 45 f4 89 c1 c1 e9 1f 01 c8 d1 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


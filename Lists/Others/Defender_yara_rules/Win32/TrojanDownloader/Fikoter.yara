rule TrojanDownloader_Win32_Fikoter_A_2147706630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fikoter.A"
        threat_id = "2147706630"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fikoter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d3 80 c2 43 52 e8 ?? ?? ?? ?? 83 c4 04 85 c0 75 0d fe c3 80 fb 04 7c e7}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ca 83 e1 03 f3 a4 89 43 f8 8b 4c 24 24 8b 44 24 10 40 83 c3 28 8b 11 33 c9 89 44 24 10 66 8b 4a 06 3b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


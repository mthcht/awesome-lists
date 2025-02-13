rule TrojanDownloader_Win32_Dumcus_A_2147624061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dumcus.A"
        threat_id = "2147624061"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dumcus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 70 0f 85 81 00 00 00 0f be 46 01 50 e8 ?? ?? ?? ?? 59 83 f8 61 75 71 0f be 46 02 50 e8 ?? ?? ?? ?? 59 83 f8 73}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 d8 1b c0 f7 d8 40 40 03 cf 00 01 47 eb d9}  //weight: 1, accuracy: High
        $x_1_3 = {73 76 63 68 6f 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


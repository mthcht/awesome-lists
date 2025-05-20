rule TrojanDownloader_Win32_Ulise_AUL_2147941770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ulise.AUL!MTB"
        threat_id = "2147941770"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 d2 8b c1 be e8 03 00 00 f7 f6 69 d2 e8 03 00 00 89 45 f8 89 55 fc 33 f6 46 41 f7 d9 1b c9 8d 45 f8 23 c8 51 6a 00 6a 00 8d 85 f4 fe ff ff 50 6a 00 89 b5 f4 fe ff ff 89 bd f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


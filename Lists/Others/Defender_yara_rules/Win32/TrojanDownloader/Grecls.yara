rule TrojanDownloader_Win32_Grecls_A_2147599153_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Grecls.A"
        threat_id = "2147599153"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Grecls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 04 00 00 00 33 d2 8b 03 e8 ?? ?? ff ff 8b 85 ?? ff ff ff ba ?? ?? 10 00 e8 ?? ?? ff ff 75 7a 8d 8d ?? ff ff ff ba 01 00 00 00 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


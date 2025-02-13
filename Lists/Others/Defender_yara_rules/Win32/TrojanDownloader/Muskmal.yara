rule TrojanDownloader_Win32_Muskmal_A_2147710027_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Muskmal.A"
        threat_id = "2147710027"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Muskmal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 08 66 33 d1 e8 ?? ?? ?? ?? 8b 95 dc fe ff ff 8b 45 f2 e8 ?? ?? ?? ?? 8b 45 f2 33 c0 8a 45 ee 66 03 45 f6 66 69 c0 14 6f 66 05 6a 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


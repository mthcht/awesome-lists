rule TrojanDownloader_Win32_Remetrac_A_2147618569_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Remetrac.A"
        threat_id = "2147618569"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Remetrac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 72 00 00 00 e8 ?? ?? ff ff ff b5 ?? ?? ff ff 8d 95 ?? ?? ff ff b8 65 00 00 00 e8 ?? ?? ff ff ff b5 ?? ?? ff ff 8d 95 ?? ?? ff ff b8 63 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d6 83 c2 04 88 02 c6 03 e9 47 8b 45 f4 89 07 8d 45 f0 50 8b 45 f0 50 6a 05 53 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


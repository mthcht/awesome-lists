rule TrojanDownloader_Win32_Coswid_A_2147654446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Coswid.A"
        threat_id = "2147654446"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Coswid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 c0 27 09 00 ff 15 ?? ?? ?? ?? eb ?? 68 40 77 1b 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e8 44 89 85 f4 6f fe ff 83 bd f4 6f fe ff 2f 77 ?? 8b 95 f4 6f fe ff 33 c9 8a 8a ?? ?? ?? ?? ff 24 8d ?? ?? ?? ?? 8d 85 00 70 fe ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


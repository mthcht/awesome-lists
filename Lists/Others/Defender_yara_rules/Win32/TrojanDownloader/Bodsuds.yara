rule TrojanDownloader_Win32_Bodsuds_A_2147623520_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bodsuds.A"
        threat_id = "2147623520"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bodsuds"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b c6 74 67 8d 8c 24 ?? ?? 00 00 2b c1 40 50 8b c1 50 8d 84 24 ?? ?? 00 00 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 54 24 30 85 c0 74 0b ff 44 24 10 83 7c 24 10 14 7c da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


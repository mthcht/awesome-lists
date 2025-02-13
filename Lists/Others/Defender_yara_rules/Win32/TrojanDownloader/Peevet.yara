rule TrojanDownloader_Win32_Peevet_A_2147634358_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Peevet.A"
        threat_id = "2147634358"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Peevet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 00 7a 00 31 00 39 00 2e 00 63 00 6f 00 6d 00 00 00 0a 00 00 00 64 00 6f 00 77 00 6e 00 32 00 00 00 0a 00 00 00 2f 00 6d 00 79 00 69 00 65 00 00 00 14 00 00 00 70 00 61 00 79 00 75 00 73 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


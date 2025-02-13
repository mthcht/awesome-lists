rule TrojanDownloader_Win32_Sdc_A_2147629354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sdc.A"
        threat_id = "2147629354"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 51 50 65 74 4c 6f 76 65 2e 64 6c 6c 00 68 74 74 70 3a 2f 2f 77 77 77 2e 6a 6e 61 6a 74 2e 63 6f 6d 2e 63 6e 2f 73 64 2e 65 78 65 00 01 00 00 00 00 00 00 00 63 3a 5c 63 2e 65 78 65 00 38 00 00 00 6d 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


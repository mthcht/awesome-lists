rule TrojanDownloader_Win32_Srotgnat_A_2147646483_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Srotgnat.A"
        threat_id = "2147646483"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Srotgnat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 e8 9f 00 00 00 53 e8 20 00 00 00 e8 36 00 00 00 53 e8 c2 ff ff ff 01 c3 80 3b 00 74 02 eb e0 31 c0 50 e8 b9 00 00 00 83 c4 04 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


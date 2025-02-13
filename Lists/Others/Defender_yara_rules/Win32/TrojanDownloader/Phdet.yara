rule TrojanDownloader_Win32_Phdet_E_2147647983_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phdet.E"
        threat_id = "2147647983"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 51 30 85 c0 7c 27 ff 75 f4 68}  //weight: 1, accuracy: High
        $x_1_2 = {81 7d f0 c8 00 00 00 75 5a bb 62 29 21 1a}  //weight: 1, accuracy: High
        $x_1_3 = "--SERVICE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


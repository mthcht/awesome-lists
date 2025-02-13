rule TrojanDownloader_Win32_Rotbope_A_2147647564_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rotbope.A"
        threat_id = "2147647564"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rotbope"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 6f 62 6f 74 2d 74 61 6f 62 61 6f 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_2 = "navidavideo" ascii //weight: 1
        $x_1_3 = {61 62 63 64 65 66 74 67 65 74 64 77 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 62 63 2e 72 65 67 00 73 76 63 68 6f 73 74 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_Aningik_A_2147716934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Aningik.A"
        threat_id = "2147716934"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Aningik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 fc 8b 7d fc b8 5b 5a 6f 6e 89 07 b8 65 54 72 61 89 47 04 b8 6e 73 66 65}  //weight: 1, accuracy: High
        $x_1_2 = {53 68 80 00 00 00 6a 04 53 6a 07 68 00 00 00 40 8d 8d 28 fd ff ff 51 ff d0 8b f0 83 fe ff 0f 84 80 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8d 45 bc 50 ff d7 85 c0 75 06 46 83 fe 05 7c f0 8b fb}  //weight: 1, accuracy: High
        $x_1_4 = "/r.php?f=e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


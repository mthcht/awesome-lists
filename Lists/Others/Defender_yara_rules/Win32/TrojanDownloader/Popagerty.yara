rule TrojanDownloader_Win32_Popagerty_A_2147649303_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Popagerty.A"
        threat_id = "2147649303"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Popagerty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 6f 67 6f 70 6f 70 5c 67 6f 67 6f 70 6f 70 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 6f 70 75 70 67 75 69 64 65 5f 53 65 74 75 70 5f 73 69 6c 65 6e 74 5f 00}  //weight: 1, accuracy: High
        $x_1_3 = {64 6f 77 6e 2e 70 6f 70 2d 75 70 67 75 69 64 65 2e 63 6f 6d 2f 73 65 74 75 70 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_Meac_A_2147683082_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Meac.A"
        threat_id = "2147683082"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Meac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 00 2e 54 4d 50 c6 40 04 00}  //weight: 1, accuracy: High
        $x_2_2 = {c7 00 5c 4d 69 63 c7 40 04 4e 73 5c 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_Bledox_B_2147678771_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bledox.B"
        threat_id = "2147678771"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bledox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 4d 53 75 70 64 61 74 65 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 72 75 70 64 00}  //weight: 1, accuracy: High
        $x_1_3 = "--FascistFirewall 1" ascii //weight: 1
        $x_1_4 = "\\cf_.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_Costrib_A_2147733854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Costrib.A"
        threat_id = "2147733854"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Costrib"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://138.204.171.108/BxjL5iKld8.zip" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


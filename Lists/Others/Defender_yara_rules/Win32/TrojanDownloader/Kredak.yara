rule TrojanDownloader_Win32_Kredak_2147689810_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kredak"
        threat_id = "2147689810"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kredak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "thaidriver.net" ascii //weight: 2
        $x_2_2 = "%s\\o.txt" ascii //weight: 2
        $x_2_3 = "%s/h_v.html" ascii //weight: 2
        $x_2_4 = "[AKED!]" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


rule TrojanDownloader_Win32_Tearspear_L_2147633324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tearspear.L"
        threat_id = "2147633324"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tearspear"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.yihaha.net/" ascii //weight: 1
        $x_1_2 = "geturlip.asp?go" ascii //weight: 1
        $x_1_3 = "bdalipayClick" ascii //weight: 1
        $x_1_4 = "OnDownloadComplete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


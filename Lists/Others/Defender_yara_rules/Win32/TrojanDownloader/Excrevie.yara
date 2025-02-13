rule TrojanDownloader_Win32_Excrevie_A_2147718176_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Excrevie.A"
        threat_id = "2147718176"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Excrevie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sc create CHNGTSvc binPath= \"c:\\exervice.exe http://" ascii //weight: 1
        $x_1_2 = "sc start prontspooler" ascii //weight: 1
        $x_1_3 = "download/xpack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


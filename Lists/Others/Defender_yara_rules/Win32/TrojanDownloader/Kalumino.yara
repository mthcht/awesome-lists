rule TrojanDownloader_Win32_Kalumino_A_2147706538_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kalumino.A"
        threat_id = "2147706538"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kalumino"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.girlliuxiaowei.com/home/eip_oursurfing.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


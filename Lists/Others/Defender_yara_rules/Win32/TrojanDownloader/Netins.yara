rule TrojanDownloader_Win32_Netins_A_2147632269_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Netins.A"
        threat_id = "2147632269"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Netins"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Program Files\\Common Files\\%I64u.jpg" ascii //weight: 1
        $x_1_2 = "count=%d|%d&data=%s&copy=%s&info=%s&act=debug" ascii //weight: 1
        $x_1_3 = "NetInstaller2010" ascii //weight: 1
        $x_1_4 = "NetGeter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


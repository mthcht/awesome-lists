rule TrojanDownloader_Win32_Encriyoko_A_2147663759_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Encriyoko.A"
        threat_id = "2147663759"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Encriyoko"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "on hijacked connection" ascii //weight: 1
        $x_1_2 = "sourceslang.iwebs.ws/downs/zdx.tgz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


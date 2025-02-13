rule TrojanDownloader_Win32_Codumwis_B_2147706069_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Codumwis.B"
        threat_id = "2147706069"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Codumwis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MicorSoft\\Windows\\CurrentVersion\\Uninstall\\360" ascii //weight: 1
        $x_1_2 = "int.dpool.sina.com.cn/iplookup/iplookup.php" ascii //weight: 1
        $x_1_3 = "http://t.cn" ascii //weight: 1
        $x_1_4 = "SoHuVA_4.2.0.16-c204900003-ng-nti-tp-s-x.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


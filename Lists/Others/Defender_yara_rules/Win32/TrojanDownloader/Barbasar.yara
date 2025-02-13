rule TrojanDownloader_Win32_Barbasar_2147725774_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Barbasar"
        threat_id = "2147725774"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Barbasar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://s3-ap-northeast-1.amazonaws.com/update-secure/asmsgrbarb.zip" ascii //weight: 1
        $x_1_2 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" ascii //weight: 1
        $x_1_3 = "http://www.moliv.com.br/stat/email0702/" ascii //weight: 1
        $x_1_4 = "Software\\Borland\\Database Engine" ascii //weight: 1
        $x_1_5 = "A transaction is already active" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_Lemmy_U_2147512141_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lemmy.U"
        threat_id = "2147512141"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lemmy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 53 73 6f 72 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "Value(jimmyhelp" ascii //weight: 1
        $x_1_3 = "moBrowser_BeforeNavigate" ascii //weight: 1
        $x_1_4 = "sendemailtoreg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


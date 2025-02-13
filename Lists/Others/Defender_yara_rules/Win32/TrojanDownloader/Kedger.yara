rule TrojanDownloader_Win32_Kedger_B_2147825968_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kedger.B!dha"
        threat_id = "2147825968"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kedger"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Number&%sOrder&%sContent&%s&EndAll" ascii //weight: 1
        $x_1_2 = "?Number=%s1&SiteId=%s" ascii //weight: 1
        $x_1_3 = "Ip=%sNa=%s" ascii //weight: 1
        $x_1_4 = "UpFailed" ascii //weight: 1
        $x_1_5 = "UpSuccess" ascii //weight: 1
        $x_1_6 = "DF%05d.tmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


rule TrojanDownloader_Win32_Popal_A_2147689624_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Popal.A"
        threat_id = "2147689624"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Popal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "D:\\POP\\Release\\pop" ascii //weight: 4
        $x_4_2 = "http://www.menaon.com/downloo/pop3.exe" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


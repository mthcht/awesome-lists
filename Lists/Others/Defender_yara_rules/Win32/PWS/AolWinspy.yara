rule PWS_Win32_AolWinspy_B_2147597959_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/AolWinspy.B"
        threat_id = "2147597959"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "AolWinspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VB98\\VB6.OLB" ascii //weight: 1
        $x_1_2 = "78E1BDD1-9941-11cf-9756-00AA00C00908" wide //weight: 1
        $x_1_3 = "DartFtp.dll" ascii //weight: 1
        $x_1_4 = "DartFtpCtl.Ftp" ascii //weight: 1
        $x_1_5 = "software\\microsoft\\DbgClr\\7.1\\fonts\\mru" wide //weight: 1
        $x_1_6 = "Write AOL Mail To " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


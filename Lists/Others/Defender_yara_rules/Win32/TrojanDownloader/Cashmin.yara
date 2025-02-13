rule TrojanDownloader_Win32_Cashmin_A_2147602455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cashmin.A"
        threat_id = "2147602455"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cashmin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Interneta Explora" ascii //weight: 1
        $x_1_2 = "http://advadmin.biz/tasks" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\run" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE" ascii //weight: 1
        $x_1_6 = "FirewallDisableNotify" ascii //weight: 1
        $x_1_7 = "UpdatesDisableNotify" ascii //weight: 1
        $x_1_8 = "AntiVirusDisableNotify" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


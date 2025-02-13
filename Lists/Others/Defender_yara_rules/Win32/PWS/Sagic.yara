rule PWS_Win32_Sagic_2147582341_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sagic.gen!kit"
        threat_id = "2147582341"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sagic"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "kit: virus constructor"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Disable taskmgr" ascii //weight: 1
        $x_1_2 = "Disable RegEdit" ascii //weight: 1
        $x_1_3 = "Alt + 0" ascii //weight: 1
        $x_2_4 = "powerFull password" ascii //weight: 2
        $x_1_5 = "ExpIorer.exe" ascii //weight: 1
        $x_1_6 = "taskmgr_32.exe" ascii //weight: 1
        $x_1_7 = "system_32.exe" ascii //weight: 1
        $x_1_8 = "intranet.exe" ascii //weight: 1
        $x_1_9 = "Yahoo! ID" ascii //weight: 1
        $x_1_10 = "MyPic.jpg.scr" ascii //weight: 1
        $x_1_11 = "MyPic.jpg.exe" ascii //weight: 1
        $x_1_12 = "MyPic.jpg.pif" ascii //weight: 1
        $x_1_13 = "Firewall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((12 of ($x_1_*))) or
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}


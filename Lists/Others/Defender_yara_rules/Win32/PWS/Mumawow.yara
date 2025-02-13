rule PWS_Win32_Mumawow_2147582040_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mumawow"
        threat_id = "2147582040"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mumawow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Text:%s" ascii //weight: 1
        $x_1_2 = "Pass:%s" ascii //weight: 1
        $x_1_3 = "User:%s" ascii //weight: 1
        $x_1_4 = "wow.exe" ascii //weight: 1
        $x_1_5 = "FindWowPass!" ascii //weight: 1
        $x_1_6 = "Erfolg!!" ascii //weight: 1
        $x_1_7 = "Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_8 = "at %d:%d cmd /c copy \"%s\" \"%s\"" ascii //weight: 1
        $x_1_9 = "net start Schedule" ascii //weight: 1
        $x_1_10 = "sc config Schedule start= auto" ascii //weight: 1
        $x_2_11 = "%s?MailBody=%s" ascii //weight: 2
        $x_1_12 = "Explorer_Server" ascii //weight: 1
        $x_2_13 = "mutex:0" ascii //weight: 2
        $x_1_14 = "svchpst.exe" ascii //weight: 1
        $x_1_15 = "World of Warcraft" ascii //weight: 1
        $x_1_16 = "GxWindowClassD3d" ascii //weight: 1
        $x_1_17 = "realmlist.wtf" ascii //weight: 1
        $x_2_18 = ".com.cn/yu/sendmail." ascii //weight: 2
        $x_1_19 = "%s%d.exe" ascii //weight: 1
        $x_1_20 = "%s%d.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((15 of ($x_1_*))) or
            ((1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_2_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}


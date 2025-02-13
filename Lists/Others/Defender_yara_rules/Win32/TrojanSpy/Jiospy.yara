rule TrojanSpy_Win32_Jiospy_B_2147592947_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Jiospy.B"
        threat_id = "2147592947"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Jiospy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://jiaozhu" ascii //weight: 10
        $x_5_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 5
        $x_1_3 = "%%comspec%% /c %s %s" ascii //weight: 1
        $x_1_4 = "@echo off" ascii //weight: 1
        $x_1_5 = "if not exist \"\"%1\"\" goto done" ascii //weight: 1
        $x_1_6 = "del /F \"\"%1\"\"" ascii //weight: 1
        $x_1_7 = "del \"\"%1\"\"" ascii //weight: 1
        $x_1_8 = "goto start" ascii //weight: 1
        $x_1_9 = "del /F %temp%" ascii //weight: 1
        $x_1_10 = "s.bat" ascii //weight: 1
        $x_1_11 = "del %temp%" ascii //weight: 1
        $x_1_12 = "%s\\rs.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


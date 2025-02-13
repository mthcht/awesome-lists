rule Trojan_Win32_Batpenr_A_2147763780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Batpenr.A!MTB"
        threat_id = "2147763780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Batpenr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "if %cr%==28 copy %temp%\\one.rtf %userprofile%\\Desktop\\OPENMEOPENMEOPENMEOPENMEOPEN" ascii //weight: 10
        $x_1_2 = "taskkill /f /im explorer.exe" ascii //weight: 1
        $x_1_3 = "taskkill /f /im taskmgr.exe" ascii //weight: 1
        $x_1_4 = "shutdown /f /r /t 0" ascii //weight: 1
        $x_1_5 = "del /f /s /q %userprofile%\\Desktop\\*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


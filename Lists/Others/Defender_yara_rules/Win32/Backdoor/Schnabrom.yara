rule Backdoor_Win32_Schnabrom_GTC_2147836085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Schnabrom.GTC!MTB"
        threat_id = "2147836085"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Schnabrom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Screensaver.scr" ascii //weight: 1
        $x_1_2 = "/C timeout 5 & del /F /Q" ascii //weight: 1
        $x_1_3 = "RHJvcEV4ZWM=" ascii //weight: 1
        $x_1_4 = "Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
        $x_1_6 = "/commands.php" ascii //weight: 1
        $x_1_7 = "\\desktop.ini" ascii //weight: 1
        $x_1_8 = "FC:\\Windows\\system32\\SHELL32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


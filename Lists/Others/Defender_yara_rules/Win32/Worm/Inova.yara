rule Worm_Win32_Inova_A_2147643959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Inova.A"
        threat_id = "2147643959"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Inova"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/*    [*]Keylog               */" ascii //weight: 1
        $x_1_2 = "reg add HKcU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v" ascii //weight: 1
        $x_1_3 = "xcopy %CD%\\autorun.inf /Y /h /k /r %WINDIR%\\systray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


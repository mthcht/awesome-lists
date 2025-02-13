rule TrojanDropper_Win32_Chayka_A_2147616275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Chayka.A"
        threat_id = "2147616275"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Chayka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HookInit" ascii //weight: 10
        $x_10_2 = "svrhost.exe" ascii //weight: 10
        $x_10_3 = "del /F \".\\%s" ascii //weight: 10
        $x_10_4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 10
        $x_1_5 = "dbldrv.dll" ascii //weight: 1
        $x_1_6 = "dbxdrv.dll" ascii //weight: 1
        $x_1_7 = "{E5723643-40A4-42c0-87D5-23DEEE0B2C5F}" ascii //weight: 1
        $x_1_8 = "{64D45A93-00DD-41cb-A187-FF02A15AE32B}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule HackTool_Win32_SunriseUnlocker_A_2147645699_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SunriseUnlocker.A"
        threat_id = "2147645699"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SunriseUnlocker"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "commandLinkUnlock" wide //weight: 1
        $x_1_2 = "affcs.cat" ascii //weight: 1
        $x_2_3 = "FormSunrise8Unlocker" ascii //weight: 2
        $x_2_4 = "Sunrise 8 Unlocker.exe" ascii //weight: 2
        $x_2_5 = "Microsoft.WindowsAPICodePack.Shell" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


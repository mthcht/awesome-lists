rule TrojanDropper_Win32_Frovserp_B_2147687508_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Frovserp.B"
        threat_id = "2147687508"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Frovserp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\drivers\\giu.sys" wide //weight: 10
        $x_10_2 = "deleteme.bat" wide //weight: 10
        $x_1_3 = "TextLog.dat" wide //weight: 1
        $x_1_4 = "My_DriverLinkName_test" wide //weight: 1
        $x_1_5 = "PMLauncher.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


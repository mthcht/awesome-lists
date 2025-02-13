rule Worm_Win32_SoulClose_CC_2147826898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SoulClose.CC!MTB"
        threat_id = "2147826898"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SoulClose"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fuckPHG" wide //weight: 1
        $x_1_2 = "CCTV.exe" wide //weight: 1
        $x_1_3 = "kill.bat" wide //weight: 1
        $x_1_4 = "cf.exe" wide //weight: 1
        $x_1_5 = "OpenYourSoul" wide //weight: 1
        $x_1_6 = "autorun.inf" wide //weight: 1
        $x_1_7 = "[AutoRun]" wide //weight: 1
        $x_1_8 = "avp.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


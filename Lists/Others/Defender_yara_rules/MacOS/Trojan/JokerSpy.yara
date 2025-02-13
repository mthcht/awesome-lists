rule Trojan_MacOS_JokerSpy_K_2147850674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/JokerSpy.K!MTB"
        threat_id = "2147850674"
        type = "Trojan"
        platform = "MacOS: "
        family = "JokerSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XProtectCheck" ascii //weight: 1
        $x_1_2 = "CGSSessionScreenIsLocked" ascii //weight: 1
        $x_1_3 = "kMDItemDisplayName = *TCC.db" ascii //weight: 1
        $x_1_4 = "FullDiskAccess: YES" ascii //weight: 1
        $x_1_5 = "Accessibility: YES" ascii //weight: 1
        $x_1_6 = "ScreenRecording: YES" ascii //weight: 1
        $x_1_7 = "The screen is currently LOCKED!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


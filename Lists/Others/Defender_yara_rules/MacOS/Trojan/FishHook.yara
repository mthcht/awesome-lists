rule Trojan_MacOS_FishHook_A_2147748478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/FishHook.A!MTB"
        threat_id = "2147748478"
        type = "Trojan"
        platform = "MacOS: "
        family = "FishHook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Desktop/reverse-project/svn/Code/MacOSX/C&J Solutions" ascii //weight: 1
        $x_1_2 = "CJFishPoolHook startCapture" ascii //weight: 1
        $x_1_3 = "CJFishPoolHook.m" ascii //weight: 1
        $x_1_4 = "fishhook.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


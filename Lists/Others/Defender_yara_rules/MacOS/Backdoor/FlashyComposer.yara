rule Backdoor_MacOS_FlashyComposer_B_2147778882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/FlashyComposer.B!MTB"
        threat_id = "2147778882"
        type = "Backdoor"
        platform = "MacOS: "
        family = "FlashyComposer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/LaunchAgents/com.GetFlashPlayer.plist" ascii //weight: 1
        $x_1_2 = "aleks papandopulo" ascii //weight: 1
        $x_1_3 = "SN6EU36WE9" ascii //weight: 1
        $x_1_4 = "com.papandopulo.alex" ascii //weight: 1
        $x_1_5 = "downloadarchives.servehttp.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


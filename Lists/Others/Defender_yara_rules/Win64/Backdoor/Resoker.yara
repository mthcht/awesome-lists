rule Backdoor_Win64_Resoker_C_2147966373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Resoker.C!MTB"
        threat_id = "2147966373"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Resoker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "https://api.telegram.org/bot" ascii //weight: 5
        $x_5_2 = "/screenshot" ascii //weight: 5
        $x_5_3 = "/uac_max" ascii //weight: 5
        $x_5_4 = "DisableTaskMgr" ascii //weight: 5
        $x_5_5 = "Bot thread started" ascii //weight: 5
        $x_5_6 = "RESOKER STARTED [HIDDEN MODE]" ascii //weight: 5
        $x_5_7 = "Screenshot created:" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


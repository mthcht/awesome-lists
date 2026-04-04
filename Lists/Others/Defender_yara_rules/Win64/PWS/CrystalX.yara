rule PWS_Win64_CrystalX_C_2147966300_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/CrystalX.C!MTB"
        threat_id = "2147966300"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "CrystalX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "runStealer" ascii //weight: 5
        $x_5_2 = "stealScreenshot" ascii //weight: 5
        $x_5_3 = "stealUserInfo" ascii //weight: 5
        $x_5_4 = "stealDiscordTokens" ascii //weight: 5
        $x_5_5 = "stealBrowsers" ascii //weight: 5
        $x_5_6 = "getClipboardText" ascii //weight: 5
        $x_5_7 = "startWebcam" ascii //weight: 5
        $x_5_8 = "startMic" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


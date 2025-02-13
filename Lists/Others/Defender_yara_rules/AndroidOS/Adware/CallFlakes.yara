rule Adware_AndroidOS_CallFlakes_A_356298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/CallFlakes.A!MTB"
        threat_id = "356298"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "CallFlakes"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PostCallManagerSDK" ascii //weight: 1
        $x_1_2 = "loadAdBannerStartApp" ascii //weight: 1
        $x_1_3 = "www.freeappsoftheday.com" ascii //weight: 1
        $x_1_4 = "Call Terminate - Ad banner" ascii //weight: 1
        $x_1_5 = "Call Terminate - Remove" ascii //weight: 1
        $x_1_6 = "clickListenerAddContact" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


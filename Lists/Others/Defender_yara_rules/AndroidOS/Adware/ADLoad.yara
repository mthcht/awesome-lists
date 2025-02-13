rule Adware_AndroidOS_ADLoad_A_348560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/ADLoad.A!MTB"
        threat_id = "348560"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "ADLoad"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FullScreenAdActivity" ascii //weight: 1
        $x_1_2 = "shouldOverrideUrlLoading" ascii //weight: 1
        $x_1_3 = "requestAds" ascii //weight: 1
        $x_1_4 = "downloadAd" ascii //weight: 1
        $x_1_5 = "playFullscreenAd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


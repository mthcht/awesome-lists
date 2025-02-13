rule Adware_AndroidOS_Xavier_A_404467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Xavier.A!MTB"
        threat_id = "404467"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Xavier"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XavierConfigHub" ascii //weight: 1
        $x_1_2 = "onInterstitialDismissed" ascii //weight: 1
        $x_1_3 = "canShowStartAppInterstitialAdOnLaunch" ascii //weight: 1
        $x_1_4 = "showAdMobInterstitial" ascii //weight: 1
        $x_1_5 = "canShowFBInterstitialAdOnLaunch" ascii //weight: 1
        $x_1_6 = "saveStartAppConfiguration" ascii //weight: 1
        $x_1_7 = "DexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


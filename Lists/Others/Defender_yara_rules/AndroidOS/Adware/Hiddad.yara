rule Adware_AndroidOS_Hiddad_B_349149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Hiddad.B!MTB"
        threat_id = "349149"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Hiddad"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/client.config/?app=pndr2&format=json&advert_key=" ascii //weight: 1
        $x_1_2 = "&pndr_install=1" ascii //weight: 1
        $x_1_3 = "lock_enable_ad" ascii //weight: 1
        $x_1_4 = "INTENT_AD_SHOW" ascii //weight: 1
        $x_1_5 = "onAdClicked" ascii //weight: 1
        $x_1_6 = "api.jetengine.be" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Adware_AndroidOS_Hiddad_C_349445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Hiddad.C!MTB"
        threat_id = "349445"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Hiddad"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setAdLoadListener" ascii //weight: 1
        $x_1_2 = "onAdClicked" ascii //weight: 1
        $x_1_3 = "LoadApplovinFullAds" ascii //weight: 1
        $x_1_4 = "adHidden" ascii //weight: 1
        $x_1_5 = "InterstitialAd" ascii //weight: 1
        $x_1_6 = "LoadBannerFbview" ascii //weight: 1
        $x_1_7 = "setComponentEnabledSetting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_Hiddad_D_351376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Hiddad.D!MTB"
        threat_id = "351376"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Hiddad"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/TheJobChromium" ascii //weight: 2
        $x_1_2 = "/TheJobSingleton" ascii //weight: 1
        $x_1_3 = "startTheBrowser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Adware_AndroidOS_Hiddad_E_369418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Hiddad.E!MTB"
        threat_id = "369418"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Hiddad"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/register_ads.php" ascii //weight: 2
        $x_1_2 = "onAdLoaded" ascii //weight: 1
        $x_1_3 = "InterstitialAdListener" ascii //weight: 1
        $x_1_4 = "onAdClicked" ascii //weight: 1
        $x_1_5 = "registerAds().execute()" ascii //weight: 1
        $x_1_6 = "onMediaDownloaded" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Adware_AndroidOS_SAgnt_A_357284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/SAgnt.A!MTB"
        threat_id = "357284"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6d 6f 62 70 61 72 6b 2f 63 6f 6d 2f [0-32] 2f 4d 61 69 6e 41 63 74 69 76 69 74 79}  //weight: 2, accuracy: Low
        $x_2_2 = "MobPark.apk" ascii //weight: 2
        $x_2_3 = "getInstallDir" ascii //weight: 2
        $x_1_4 = "InterstitialAd" ascii //weight: 1
        $x_1_5 = "postAdmobLog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Adware_AndroidOS_SAgnt_B_357285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/SAgnt.B!MTB"
        threat_id = "357285"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ru/mail/usa/android/mytarget/ads" ascii //weight: 1
        $x_1_2 = "DexClassLoader" ascii //weight: 1
        $x_1_3 = "/system/app/Superuser.apk" ascii //weight: 1
        $x_1_4 = "MobileAds" ascii //weight: 1
        $x_1_5 = "OnAppInstallAdLoadedListener" ascii //weight: 1
        $x_1_6 = "getLaunchIntentForPackage" ascii //weight: 1
        $x_1_7 = "setJavaScriptEnabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


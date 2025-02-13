rule Adware_AndroidOS_Fictus_A_347926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Fictus.A!MTB"
        threat_id = "347926"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Fictus"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "apkfiles.com/apk-24852/ar-cleaner/" ascii //weight: 1
        $x_1_2 = "com/app/attacker/goodwork" ascii //weight: 1
        $x_1_3 = "mobileads" ascii //weight: 1
        $x_1_4 = "AdDisplayListener" ascii //weight: 1
        $x_1_5 = "loadAds" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_Fictus_B_348511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Fictus.B!MTB"
        threat_id = "348511"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Fictus"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/rixallab/ads/ads" ascii //weight: 1
        $x_1_2 = "ads01.adecosystems.com" ascii //weight: 1
        $x_1_3 = "InterstitialAd" ascii //weight: 1
        $x_1_4 = "preloadAd" ascii //weight: 1
        $x_1_5 = "com/vdopia/android/preroll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


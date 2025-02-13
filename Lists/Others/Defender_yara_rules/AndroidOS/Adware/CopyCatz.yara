rule Adware_AndroidOS_CopyCatz_A_354878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/CopyCatz.A!MTB"
        threat_id = "354878"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "CopyCatz"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "com.tdc.adservice" ascii //weight: 10
        $x_10_2 = "com.nend.adservice" ascii //weight: 10
        $x_10_3 = "com.elise.adservice" ascii //weight: 10
        $x_10_4 = "com.Vpon.adservice" ascii //weight: 10
        $x_10_5 = "com.Vungle.adservice" ascii //weight: 10
        $x_10_6 = "com.umeng.adservice" ascii //weight: 10
        $x_10_7 = "com.maio.adservice" ascii //weight: 10
        $x_1_8 = "fullAdId" ascii //weight: 1
        $x_1_9 = "requestNewInterstitial" ascii //weight: 1
        $x_1_10 = "AdsJob" ascii //weight: 1
        $x_1_11 = "adsActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


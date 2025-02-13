rule TrojanSpy_AndroidOS_Imlog_A_2147828945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Imlog.A!MTB"
        threat_id = "2147828945"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Imlog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SeachTagsActivity" ascii //weight: 1
        $x_1_2 = "GOOGLE_AD_HTML" ascii //weight: 1
        $x_1_3 = "imnet.us/ads/ewallpapers_all.html" ascii //weight: 1
        $x_1_4 = "ISSYNOK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


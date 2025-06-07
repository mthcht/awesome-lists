rule Adware_AndroidOS_BrowserAd_A_459388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/BrowserAd.A!MTB"
        threat_id = "459388"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "BrowserAd"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "openOnclickLink" ascii //weight: 1
        $x_1_2 = "dev/applabz/ad/activity/TransparentClicker" ascii //weight: 1
        $x_1_3 = {22 00 92 24 1a 01 20 b5 70 20 f9 df 10 00 60 01 dc bd 54 d1 dd bd 54 12 9e 76 6e 20 04 e0 20 00 6e 10 13 e0 00 00 0c 00 6e 10 9a 08 01 00 0c 02 1a 03 07 8d 71 20 bb e5 32 00 60 03 44 10 13 04 00 20 12 05 12 16 1a 07 4c df 13 08 1d 00 1a 09 c4 b6 12 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


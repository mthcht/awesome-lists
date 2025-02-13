rule Adware_AndroidOS_Feiad_A_359172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Feiad.A!MTB"
        threat_id = "359172"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Feiad"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/adfeiwo/" ascii //weight: 1
        $x_1_2 = "showAd" ascii //weight: 1
        $x_1_3 = "/adfeiwo/appwall/apk" ascii //weight: 1
        $x_1_4 = "com/seleuco/mame4all" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


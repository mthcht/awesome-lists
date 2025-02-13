rule Adware_AndroidOS_IconHider_A_355415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/IconHider.A!MTB"
        threat_id = "355415"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "IconHider"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mapi.1oceans.com" ascii //weight: 1
        $x_1_2 = "getClickSp" ascii //weight: 1
        $x_1_3 = "clickDelayTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


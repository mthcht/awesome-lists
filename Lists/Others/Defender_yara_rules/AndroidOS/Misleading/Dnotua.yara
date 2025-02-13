rule Misleading_AndroidOS_Dnotua_C_343390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:AndroidOS/Dnotua.C!MTB"
        threat_id = "343390"
        type = "Misleading"
        platform = "AndroidOS: Android operating system"
        family = "Dnotua"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "m.topber.com" ascii //weight: 1
        $x_1_2 = "com/example/administrator/myapplication" ascii //weight: 1
        $x_1_3 = "weixin://" ascii //weight: 1
        $x_1_4 = "dianping://" ascii //weight: 1
        $x_1_5 = "alipays://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Misleading_AndroidOS_Dnotua_D_363124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:AndroidOS/Dnotua.D!MTB"
        threat_id = "363124"
        type = "Misleading"
        platform = "AndroidOS: Android operating system"
        family = "Dnotua"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".cnanzhi.com" ascii //weight: 1
        $x_1_2 = "com/example/administrator/" ascii //weight: 1
        $x_1_3 = "loadUrl" ascii //weight: 1
        $x_1_4 = "shouldOverrideUrlLoading" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


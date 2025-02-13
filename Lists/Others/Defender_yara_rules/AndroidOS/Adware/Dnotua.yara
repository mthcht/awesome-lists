rule Adware_AndroidOS_Dnotua_A_348984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Dnotua.A!MTB"
        threat_id = "348984"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Dnotua"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/webh5/code/MainActivity" ascii //weight: 1
        $x_1_2 = "/UrlOpenTool" ascii //weight: 1
        $x_1_3 = "setJavaScriptEnabled" ascii //weight: 1
        $x_1_4 = "setDomStorageEnabled" ascii //weight: 1
        $x_1_5 = "shouldOverrideUrlLoading" ascii //weight: 1
        $x_1_6 = "canGoBack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


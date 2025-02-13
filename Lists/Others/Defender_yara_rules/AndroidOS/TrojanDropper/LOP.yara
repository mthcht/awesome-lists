rule TrojanDropper_AndroidOS_LOP_A_2147832799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/LOP.A!MTB"
        threat_id = "2147832799"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "LOP"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "hgupdate.hmapi.com" ascii //weight: 3
        $x_1_2 = "killProcess" ascii //weight: 1
        $x_1_3 = "pthrkup.do" ascii //weight: 1
        $x_1_4 = "dalvik/system/dexclassloader" ascii //weight: 1
        $x_1_5 = "SysinstallApk" ascii //weight: 1
        $x_1_6 = "func:RequestInstall" ascii //weight: 1
        $x_1_7 = "StartDwonApk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


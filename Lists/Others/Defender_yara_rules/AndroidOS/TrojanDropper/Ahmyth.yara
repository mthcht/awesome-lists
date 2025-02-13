rule TrojanDropper_AndroidOS_Ahmyth_C_2147763628_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Ahmyth.C!MTB"
        threat_id = "2147763628"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/.System/APK/" ascii //weight: 2
        $x_1_2 = "shell_exec" ascii //weight: 1
        $x_1_3 = "executeNativeCode" ascii //weight: 1
        $x_1_4 = "isPackageInstalled" ascii //weight: 1
        $x_1_5 = "installAPK" ascii //weight: 1
        $x_1_6 = "do_root" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_AndroidOS_TrickMo_A_2147922950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/TrickMo.A!MTB"
        threat_id = "2147922950"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "TrickMo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "clickerSenderArg" ascii //weight: 1
        $x_1_2 = "getStartOrInstallPackage" ascii //weight: 1
        $x_1_3 = "getScreenInfo" ascii //weight: 1
        $x_1_4 = "send_log_injects" ascii //weight: 1
        $x_1_5 = "RecordScreenUtil" ascii //weight: 1
        $x_1_6 = "openAccessibilitySettingsOrMessage" ascii //weight: 1
        $x_1_7 = "setNeedOpenAccessibilitySettings" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


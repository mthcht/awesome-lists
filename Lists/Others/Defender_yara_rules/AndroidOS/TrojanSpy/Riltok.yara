rule TrojanSpy_AndroidOS_Riltok_A_2147744678_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Riltok.A!MTB"
        threat_id = "2147744678"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Riltok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "realtalk-jni" ascii //weight: 1
        $x_1_2 = "REALTALK REQUEST" ascii //weight: 1
        $x_1_3 = "move_sms_client" ascii //weight: 1
        $x_1_4 = "setServerGate" ascii //weight: 1
        $x_1_5 = "SetJavaScriptEnabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


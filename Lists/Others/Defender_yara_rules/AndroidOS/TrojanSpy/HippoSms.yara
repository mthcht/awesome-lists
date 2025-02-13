rule TrojanSpy_AndroidOS_HippoSms_A_2147781384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/HippoSms.A!MTB"
        threat_id = "2147781384"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "HippoSms"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "message_sendsms_success" ascii //weight: 1
        $x_1_2 = "forceUpgrade" ascii //weight: 1
        $x_1_3 = "recommend_self_phonenumber" ascii //weight: 1
        $x_1_4 = "bank.html" ascii //weight: 1
        $x_1_5 = "rs_update.apk" ascii //weight: 1
        $x_1_6 = "downloading latest apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


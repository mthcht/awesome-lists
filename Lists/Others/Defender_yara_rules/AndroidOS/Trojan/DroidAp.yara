rule Trojan_AndroidOS_DroidAp_A_2147841002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DroidAp.A!MTB"
        threat_id = "2147841002"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DroidAp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_DroidPhoneStateListener" ascii //weight: 1
        $x_1_2 = "com/hbw/droidapp" ascii //weight: 1
        $x_1_3 = "CALLBASKAUTOKILL" ascii //weight: 1
        $x_1_4 = "SmsSender" ascii //weight: 1
        $x_1_5 = "_CallListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


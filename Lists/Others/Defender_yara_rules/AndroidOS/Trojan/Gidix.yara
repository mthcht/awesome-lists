rule Trojan_AndroidOS_Gidix_A_2147823813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Gidix.A!MTB"
        threat_id = "2147823813"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Gidix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsAction_Send" ascii //weight: 1
        $x_1_2 = "setMsgSlient" ascii //weight: 1
        $x_1_3 = "GetPhoneInfo" ascii //weight: 1
        $x_1_4 = "recphoneid" ascii //weight: 1
        $x_1_5 = "PhoneStatusCheck" ascii //weight: 1
        $x_1_6 = "slientCheck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


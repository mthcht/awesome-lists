rule Trojan_AndroidOS_PJapps_A_2147895675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/PJapps.A!MTB"
        threat_id = "2147895675"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "PJapps"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.test.sms.send" ascii //weight: 1
        $x_1_2 = "/mm.do?imei=" ascii //weight: 1
        $x_1_3 = "/sdcard/androidh.log" ascii //weight: 1
        $x_1_4 = "TANCActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_PJapps_B_2147899020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/PJapps.B!MTB"
        threat_id = "2147899020"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "PJapps"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "frddetailsendmsg" ascii //weight: 1
        $x_1_2 = "MsgSendActivity" ascii //weight: 1
        $x_1_3 = "LinfoSettingPersonalinfo" ascii //weight: 1
        $x_1_4 = "groupmsg_msgsend" ascii //weight: 1
        $x_1_5 = "com.test.sms.send" ascii //weight: 1
        $x_1_6 = "/sdcard/androidh.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


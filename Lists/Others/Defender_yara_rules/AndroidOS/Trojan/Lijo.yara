rule Trojan_AndroidOS_Lijo_B_2147811834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Lijo.B!MTB"
        threat_id = "2147811834"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Lijo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSGrabber" ascii //weight: 1
        $x_1_2 = "sx.jolly.partner" ascii //weight: 1
        $x_1_3 = "SAVESMSLOGS" ascii //weight: 1
        $x_1_4 = "MTBOT_NUMBER" ascii //weight: 1
        $x_1_5 = "SendLogs" ascii //weight: 1
        $x_1_6 = "sendSelfNumberToMTBot" ascii //weight: 1
        $x_1_7 = "partnerslab.comcloud/savelog/" ascii //weight: 1
        $x_1_8 = "http://partnerslab.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


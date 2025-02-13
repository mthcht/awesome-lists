rule Trojan_AndroidOS_FakeUmeng_A_2147818009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeUmeng.A!MTB"
        threat_id = "2147818009"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeUmeng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/umeng/adutils/AdsConnect" ascii //weight: 1
        $x_1_2 = "DianleHandle" ascii //weight: 1
        $x_1_3 = "/MyAd/Convert.jsp" ascii //weight: 1
        $x_1_4 = "DatouniaoHandler" ascii //weight: 1
        $x_1_5 = "smsContent" ascii //weight: 1
        $x_1_6 = "extractData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_FakeUmeng_B_2147818010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeUmeng.B!MTB"
        threat_id = "2147818010"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeUmeng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ad/Convert.jsp" ascii //weight: 1
        $x_1_2 = "SmsMask" ascii //weight: 1
        $x_1_3 = "replyIntercept" ascii //weight: 1
        $x_1_4 = "reply_keyword" ascii //weight: 1
        $x_1_5 = "extractData" ascii //weight: 1
        $x_1_6 = "isRootSystem" ascii //weight: 1
        $x_1_7 = "/sy/initConfig" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


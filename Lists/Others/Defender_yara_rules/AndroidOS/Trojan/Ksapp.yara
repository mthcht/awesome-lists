rule Trojan_AndroidOS_Ksapp_A_2147663120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ksapp.A"
        threat_id = "2147663120"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ksapp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lsd/teCer/qdtheyt/q/r;" ascii //weight: 1
        $x_1_2 = "LseC/vBOvyix/ikfuhCqhyearma/WqCuQffBysqjyed;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Ksapp_AS_2147781617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ksapp.AS!MTB"
        threat_id = "2147781617"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ksapp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "run in emulator" ascii //weight: 1
        $x_1_2 = "lastFourOfAccountNumber" ascii //weight: 1
        $x_1_3 = "FundingPlans" ascii //weight: 1
        $x_1_4 = "PayPalActivity" ascii //weight: 1
        $x_1_5 = "/DomobAppDownload/" ascii //weight: 1
        $x_1_6 = "pay_coin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


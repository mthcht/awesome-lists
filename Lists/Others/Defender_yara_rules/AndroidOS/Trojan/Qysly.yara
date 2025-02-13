rule Trojan_AndroidOS_Qysly_A_2147744573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Qysly.A!MTB"
        threat_id = "2147744573"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Qysly"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "zqpk_dl_issend_newuser_" ascii //weight: 2
        $x_1_2 = "RemoteTools.jar" ascii //weight: 1
        $x_1_3 = "com.zhiqupk.root" ascii //weight: 1
        $x_1_4 = "sST6Pr1zNrZmmF74" ascii //weight: 1
        $x_1_5 = "syllyq1n.com" ascii //weight: 1
        $x_1_6 = "wksnkys7.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


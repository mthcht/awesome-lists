rule Trojan_AndroidOS_Hippo_A_2147904541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hippo.A!MTB"
        threat_id = "2147904541"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hippo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendMessageWithLooper" ascii //weight: 1
        $x_1_2 = "/sdcard/ku6/" ascii //weight: 1
        $x_1_3 = "info.ku6.cn/clientRequest" ascii //weight: 1
        $x_1_4 = "cannelUpdate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_AndroidOS_Yzichng_A_2147751589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Yzichng.A!MTB"
        threat_id = "2147751589"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Yzichng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "api-rssocks.youzicheng.net/api/socksConfig" ascii //weight: 2
        $x_1_2 = "chmod 777 /data/data/%s/files/rssocks" ascii //weight: 1
        $x_1_3 = "/PostSthService;" ascii //weight: 1
        $x_1_4 = "iconHide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


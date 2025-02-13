rule Trojan_AndroidOS_TyStu_T_2147781965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/TyStu.T!MTB"
        threat_id = "2147781965"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "TyStu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/and/snd/Notifier" ascii //weight: 1
        $x_1_2 = "typ3studios" ascii //weight: 1
        $x_1_3 = "www.pixeltrack66.com/mt/" ascii //weight: 1
        $x_1_4 = "AdditionalApps" ascii //weight: 1
        $x_1_5 = "&mobile_number" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


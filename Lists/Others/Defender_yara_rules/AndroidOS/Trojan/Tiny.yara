rule Trojan_AndroidOS_Tiny_A_2147834040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Tiny.A!MTB"
        threat_id = "2147834040"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s_getsmscode" ascii //weight: 1
        $x_1_2 = "re_confirm_match_phone" ascii //weight: 1
        $x_1_3 = "ltpayreq" ascii //weight: 1
        $x_1_4 = "yzm_content_pre" ascii //weight: 1
        $x_1_5 = "ISPAYUNFAIRLOST" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Tiny_A_2147844812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Tiny.A"
        threat_id = "2147844812"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Tiny"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Lcom/fixup/usbhub" ascii //weight: 3
        $x_3_2 = "Lcom/start/carrier" ascii //weight: 3
        $x_3_3 = "Lcom/iperf/audiod" ascii //weight: 3
        $x_1_4 = "Receiverohtq" ascii //weight: 1
        $x_1_5 = "Serviceohtq" ascii //weight: 1
        $x_1_6 = "Receiverwkdq" ascii //weight: 1
        $x_1_7 = "Servicewkdq" ascii //weight: 1
        $x_1_8 = "Receiverfbiu" ascii //weight: 1
        $x_1_9 = "Servicefbiu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}


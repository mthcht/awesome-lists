rule Trojan_AndroidOS_Phonzy_A_2147850584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Phonzy.A"
        threat_id = "2147850584"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Phonzy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/pandora/o147/" ascii //weight: 2
        $x_1_2 = "v2api.3xx.live" ascii //weight: 1
        $x_1_3 = "DISCONNECT_REASON_CODE_UNKNOW" ascii //weight: 1
        $x_1_4 = "UploadLoopWork" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


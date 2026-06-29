rule Trojan_AndroidOS_NGate_AMTB_2147971780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/NGate!AMTB"
        threat_id = "2147971780"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "NGate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Empty PIN sent on destroy" ascii //weight: 1
        $x_1_2 = "disableReaderMode" ascii //weight: 1
        $x_1_3 = "showCard() invoked" ascii //weight: 1
        $x_1_4 = "Animations started for card display" ascii //weight: 1
        $x_1_5 = "clear_card_info" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


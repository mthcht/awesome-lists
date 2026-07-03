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

rule Trojan_AndroidOS_NGate_AMTB_2147971780_1
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
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {23 01 87 1c 26 01 32 00 00 00 69 01 e1 1c 23 01 88 1c 69 01 d5 1c 23 01 88 1c 69 01 d6 1c 23 01 88 1c 69 01 d7 1c 23 01 88 1c 69 01 d8 1c 23 01 88 1c}  //weight: 2, accuracy: High
        $x_2_2 = {69 01 d7 1c 23 01 88 1c 69 01 d8 1c 23 01 88 1c 69 01 d9 1c 23 01 88 1c 69 01 da 1c 23 01 88 1c 69 01 db 1c}  //weight: 2, accuracy: High
        $x_2_3 = {13 02 00 01 13 03 80 00 71 30 61 55 32 01 23 01 88 1c 26 01 5e 00 00 00 13 04 a0 00 71 30 61 55 42 01 23 01 88 1c 26 01 68 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


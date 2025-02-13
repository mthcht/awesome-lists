rule Trojan_AndroidOS_BlankBot_A_2147922768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BlankBot.A!MTB"
        threat_id = "2147922768"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BlankBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 28 35 81 0f 00 46 08 02 01 6e 20 a1 25 80 00 13 08 2e 00 6e 20 99 25 80 00 d8 01 01 01 28 f1}  //weight: 1, accuracy: High
        $x_1_2 = "Recording Screen!" ascii //weight: 1
        $x_1_3 = "keyCodes" ascii //weight: 1
        $x_1_4 = "tenbis/library/views/CompactCreditCardInput" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BlankBot_B_2147923939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BlankBot.B!MTB"
        threat_id = "2147923939"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BlankBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RecorderServiceasda" ascii //weight: 1
        $x_1_2 = "tenbis/library/views/CompactCreditCardInput" ascii //weight: 1
        $x_1_3 = "Inatbox" ascii //weight: 1
        $x_1_4 = "deleteSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_AndroidOS_Fakemoney_C_2147852593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakemoney.C"
        threat_id = "2147852593"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakemoney"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.hoslenalot.colpis" ascii //weight: 1
        $x_1_2 = "hopsy.info/dert.php" ascii //weight: 1
        $x_1_3 = "Oxptyvyke.settings" ascii //weight: 1
        $x_1_4 = "ZHJlYW1sYW5kaWFuLmluZm8vY2V6ay5waHA" ascii //weight: 1
        $x_1_5 = "Hgvoeyhnc" ascii //weight: 1
        $x_1_6 = "Yvckank" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


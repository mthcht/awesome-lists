rule Trojan_AndroidOS_BTMOBRat_AMTB_2147971924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BTMOBRat!AMTB"
        threat_id = "2147971924"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BTMOBRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/yaarsa/private/" ascii //weight: 2
        $x_2_2 = "BTMOB" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


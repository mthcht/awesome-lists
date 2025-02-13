rule Trojan_AndroidOS_Elibomi_A_2147794145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Elibomi.A"
        threat_id = "2147794145"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Elibomi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xvabzezitft" ascii //weight: 1
        $x_1_2 = "abxvnitid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


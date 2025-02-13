rule Trojan_AndroidOS_RealRat_P_2147926435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RealRat.P"
        threat_id = "2147926435"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RealRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&action=offlineOff&screen=" ascii //weight: 2
        $x_2_2 = "_bank_findbalance" ascii //weight: 2
        $x_2_3 = "_checkscreenstatus" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


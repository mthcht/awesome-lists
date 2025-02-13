rule Trojan_AndroidOS_Citmo_A_2147678312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Citmo.A"
        threat_id = "2147678312"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Citmo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsblocker" ascii //weight: 1
        $x_1_2 = "Auth Request to:" ascii //weight: 1
        $x_1_3 = "hide SMS" ascii //weight: 1
        $x_1_4 = "m/as225kerto" ascii //weight: 1
        $x_1_5 = "activity_code" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


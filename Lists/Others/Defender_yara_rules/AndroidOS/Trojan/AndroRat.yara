rule Trojan_AndroidOS_AndroRat_A_2147794863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/AndroRat.A"
        threat_id = "2147794863"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "AndroRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "start_cap_screen" ascii //weight: 2
        $x_1_2 = "smslg=" ascii //weight: 1
        $x_2_3 = "unsetNotif" ascii //weight: 2
        $x_2_4 = "smsMoniter<" ascii //weight: 2
        $x_1_5 = "set_EnbgpsService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


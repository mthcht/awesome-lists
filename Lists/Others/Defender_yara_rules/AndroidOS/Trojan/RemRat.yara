rule Trojan_AndroidOS_RemRat_A_2147782519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RemRat.A"
        threat_id = "2147782519"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RemRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lrem/company/com/rem/Tasks/SE/Viberation" ascii //weight: 2
        $x_2_2 = "/.photos/" ascii //weight: 2
        $x_2_3 = "/.calls/" ascii //weight: 2
        $x_1_4 = "/system/app/Superuser.apk" ascii //weight: 1
        $x_1_5 = "/data/local/xbin/su" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


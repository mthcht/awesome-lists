rule Trojan_AndroidOS_Sova_A_2147793882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Sova.A"
        threat_id = "2147793882"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Sova"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "startddos" ascii //weight: 4
        $x_4_2 = "scaninject" ascii //weight: 4
        $x_4_3 = "forinject.php" ascii //weight: 4
        $x_2_4 = "stophidensms" ascii //weight: 2
        $x_2_5 = "starthidenpush" ascii //weight: 2
        $x_1_6 = "stealer" ascii //weight: 1
        $x_1_7 = "delbot" ascii //weight: 1
        $x_1_8 = "startkeylog" ascii //weight: 1
        $x_1_9 = "send_cookie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_4_*) and 3 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}


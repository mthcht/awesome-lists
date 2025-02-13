rule Trojan_AndroidOS_Teardroid_K_2147894347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Teardroid.K"
        threat_id = "2147894347"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Teardroid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "removeBatterOpt" ascii //weight: 2
        $x_2_2 = "com/example/teardroidv2/Revive" ascii //weight: 2
        $x_2_3 = "getVictimDatastore" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Teardroid_A_2147899821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Teardroid.A"
        threat_id = "2147899821"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Teardroid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{\"success\":true}" ascii //weight: 1
        $x_1_2 = "{\"error\":\"No contact found!\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


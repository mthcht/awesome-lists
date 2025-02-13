rule Trojan_AndroidOS_Gossrat_A_2147895311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Gossrat.A"
        threat_id = "2147895311"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Gossrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NhtyFXJvzko8PL+g9+xU5w==" ascii //weight: 1
        $x_1_2 = "SfffkyqARXB2dg4KozzZ8g==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


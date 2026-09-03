rule Trojan_Linux_ShaiWorm_SG_2147977445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ShaiWorm.SG"
        threat_id = "2147977445"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ShaiWorm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "__IS_DAEMON=1" wide //weight: 10
        $x_10_2 = "bun" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Linux_ClickFix_SA_2147941986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ClickFix.SA"
        threat_id = "2147941986"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "salorttactical.top/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


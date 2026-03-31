rule Trojan_Linux_Rbot_BR2_2147965996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Rbot.BR2"
        threat_id = "2147965996"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Rbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/botpilled/rbot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


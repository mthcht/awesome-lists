rule Trojan_Linux_Moobot_B_2147817651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Moobot.B"
        threat_id = "2147817651"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Moobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii //weight: 3
        $x_3_2 = "Self Rep Fucking NeTiS and Thisity" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Moobot_D_2147817652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Moobot.D"
        threat_id = "2147817652"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Moobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/bin/busybox DNXXXFF" ascii //weight: 2
        $x_2_2 = "verify:OK" ascii //weight: 2
        $x_2_3 = "randNum:" ascii //weight: 2
        $x_2_4 = "qE6MGAbI" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


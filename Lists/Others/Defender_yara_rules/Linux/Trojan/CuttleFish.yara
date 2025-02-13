rule Trojan_Linux_CuttleFish_A_2147909436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CuttleFish.A!MTB"
        threat_id = "2147909436"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CuttleFish"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "interface -k killold agent" ascii //weight: 1
        $x_1_2 = "sniffer nic" ascii //weight: 1
        $x_1_3 = "/tmp/.putin" ascii //weight: 1
        $x_1_4 = "http_rule_hearttime" ascii //weight: 1
        $x_1_5 = "http_hijack_hearttime" ascii //weight: 1
        $x_1_6 = "/tmp/thconfigjs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


rule Trojan_Linux_AvRecon_A_2147889552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/AvRecon.A!MTB"
        threat_id = "2147889552"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "AvRecon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/model.txt" ascii //weight: 1
        $x_1_2 = "X-Proto-Storage" ascii //weight: 1
        $x_1_3 = "X-Proto-Jid" ascii //weight: 1
        $x_1_4 = "VILKA" ascii //weight: 1
        $x_1_5 = "?pet=maral&age=" ascii //weight: 1
        $x_1_6 = "dnssmasq" ascii //weight: 1
        $x_1_7 = "757A6D7E336D6D" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


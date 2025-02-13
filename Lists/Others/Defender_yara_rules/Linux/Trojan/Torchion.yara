rule Trojan_Linux_Torchion_A_2147838291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Torchion.A"
        threat_id = "2147838291"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Torchion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/etc/resolv.conf" ascii //weight: 1
        $x_1_2 = "/etc/hosts" ascii //weight: 1
        $x_1_3 = "/etc/passwd" ascii //weight: 1
        $x_1_4 = ".ssh" ascii //weight: 1
        $x_1_5 = ".gitconfig" ascii //weight: 1
        $x_10_6 = "getNameservers" ascii //weight: 10
        $x_10_7 = "gatherFiles" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


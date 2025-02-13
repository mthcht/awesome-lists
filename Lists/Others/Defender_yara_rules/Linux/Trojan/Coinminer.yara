rule Trojan_Linux_Coinminer_B_2147818703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Coinminer.B"
        threat_id = "2147818703"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Coinminer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".onion" ascii //weight: 1
        $x_1_2 = ".i2p" ascii //weight: 1
        $x_1_3 = "start_mining" ascii //weight: 1
        $x_1_4 = "stop_mining" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


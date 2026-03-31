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

rule Trojan_Linux_Coinminer_TS9_2147965998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Coinminer.TS9"
        threat_id = "2147965998"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Coinminer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {78 00 6d 00 72 00 [0-8] 2e 00 6b 00 72 00 79 00 70 00 74 00 65 00 78 00 2e 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_DeliveryCheck_B_2147892813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DeliveryCheck.B!dha"
        threat_id = "2147892813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DeliveryCheck"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {08 06 1a 58 4a 03 06 1a 58 4a 03 8e 69 5d 91 9e}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DeliveryCheck_B_2147892813_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DeliveryCheck.B!dha"
        threat_id = "2147892813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DeliveryCheck"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b 56 08 17 58 20 00 01 00 00 5d 0c 09 06 08 94 58 20 00 01 00 00 5d 0d 06 08 94 13 09 06 08 06 09 94 9e 06 09 11 09 9e 06 06 08 94 06 09 94 58 20 00 01 00 00 5d 94 1a 2c ac 13 0a 11 04 11 08}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


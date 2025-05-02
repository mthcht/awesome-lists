rule Trojan_MSIL_SnakeKeyLgger_MNO_2147925014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLgger.MNO!MTB"
        threat_id = "2147925014"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLgger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 9c 06 00 70 38 b2 00 00 00 38 b7 00 00 00 72 ce 06 00 70 38 b3 00 00 00 1e 3a b7 00 00 00 26 38 b7 00 00 00 38 bc 00 00 00 12 02 38 bb 00 00 00 75 4a 00 00 1b 38 bb 00 00 00 16 2d e2 12 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLgger_CZ_2147940545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLgger.CZ!MTB"
        threat_id = "2147940545"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLgger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 19 8d 01 00 00 01 25 16 12 07 20 d4 02 00 00 20 cf 02 00 00 28 91 00 00 06 9c 25 17 12 07 20 4f 01 00 00 20 53 01 00 00 28 91 00 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


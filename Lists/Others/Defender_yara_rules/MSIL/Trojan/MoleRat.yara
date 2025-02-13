rule Trojan_MSIL_MoleRat_ALCN_2147839131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MoleRat.ALCN!MTB"
        threat_id = "2147839131"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MoleRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 8e 69 1a 5d 0a 03 8e 69 1a 5b 0b 03 8e 69 8d 29 02 00 01 0c 02 7b fb 73 00 04 8e 69 1a 5b 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_PredatorPain_KAA_2147924316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PredatorPain.KAA!MTB"
        threat_id = "2147924316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PredatorPain"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0a 1c 13 04 2b b7 0e 04 05 61 1f 77 59 06 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_PredatorPainRAT_A_2147839990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PredatorPainRAT.A!MTB"
        threat_id = "2147839990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PredatorPainRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 04 06 1a 58 91 06 28 ?? 00 00 06 61 d2 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


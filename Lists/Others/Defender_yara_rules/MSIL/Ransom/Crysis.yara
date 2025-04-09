rule Ransom_MSIL_Crysis_AJQA_2147938272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crysis.AJQA!MTB"
        threat_id = "2147938272"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {08 11 05 02 11 05 91 07 61 11 04 06 91 61 b4 9c 1d 13 07 38 ?? ff ff ff 7e ?? 00 00 04 16 8c ?? 00 00 01 28 ?? 00 00 06 26}  //weight: 3, accuracy: Low
        $x_2_2 = {02 8e b7 17 d6 8d 5a 00 00 01 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


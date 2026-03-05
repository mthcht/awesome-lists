rule Ransom_MSIL_MSILHeracles_SN_2147964162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/MSILHeracles.SN!MTB"
        threat_id = "2147964162"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILHeracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {6f 23 00 00 0a 17 73 24 00 00 0a 13 0b 11 07 19 73 21 00 00 0a 13 0c 2b 0a 11 0b 11 0d d2 6f 25 00 00 0a 11 0c 6f 26 00 00 0a 25 13 0d 15 33 e9 11 0c 6f 27 00 00 0a 11 0b 6f 27 00 00 0a 11 09 6f 27 00 00 0a 11 07 28 ?? 00 00 0a de 03}  //weight: 4, accuracy: Low
        $x_2_2 = "$7CF99B23-CE07-43FE-8279-B7E8BDD9BE8C" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


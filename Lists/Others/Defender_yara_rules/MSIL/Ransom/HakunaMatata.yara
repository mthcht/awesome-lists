rule Ransom_MSIL_HakunaMatata_SWL_2147925455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HakunaMatata.SWL!MTB"
        threat_id = "2147925455"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HakunaMatata"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Hakuna Matata 2.3" ascii //weight: 2
        $x_2_2 = "#ENCRYPT_EXTENSIONS" ascii //weight: 2
        $x_1_3 = "$d4d54c73-c442-4f8a-a94c-614cbe7282f3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


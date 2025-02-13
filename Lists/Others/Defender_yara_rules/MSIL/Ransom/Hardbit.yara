rule Ransom_MSIL_Hardbit_SK_2147893329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hardbit.SK!MTB"
        threat_id = "2147893329"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hardbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "VTtfvhJFsVTtfJFsVTtf.Resources.resources" ascii //weight: 2
        $x_2_2 = "VTtfvhJFsVTtfJFsVTtfhid.Resources.resources" ascii //weight: 2
        $x_1_3 = "$540c4d38-7ff8-4851-bcb7-ca49604cb428" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


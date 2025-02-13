rule Ransom_MSIL_PolyRansom_ABI_2147830424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/PolyRansom.ABI!MTB"
        threat_id = "2147830424"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PolyRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 09 6f 35 ?? ?? 0a 07 6f 36 ?? ?? 0a 08 6f 37 ?? ?? 0a 09 6f 38 ?? ?? 0a 13 04 de 1a}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "GetTempPath" ascii //weight: 1
        $x_1_4 = "GetDecoderStream" ascii //weight: 1
        $x_1_5 = "CmRccService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


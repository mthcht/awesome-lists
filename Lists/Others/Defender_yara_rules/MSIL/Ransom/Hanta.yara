rule Ransom_MSIL_Hanta_DA_2147780808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hanta.DA!MTB"
        threat_id = "2147780808"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hanta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hanta_2_0_offline" ascii //weight: 1
        $x_1_2 = "ToBase64String" ascii //weight: 1
        $x_1_3 = "get_IsAlive" ascii //weight: 1
        $x_1_4 = "IsLogging" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Convert" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


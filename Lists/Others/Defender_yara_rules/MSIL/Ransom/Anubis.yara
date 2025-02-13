rule Ransom_MSIL_Anubis_DA_2147787781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Anubis.DA!MTB"
        threat_id = "2147787781"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Anubis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Anubis" ascii //weight: 1
        $x_1_2 = "QW51YmlzJQ==" ascii //weight: 1
        $x_1_3 = "_Encrypted$" ascii //weight: 1
        $x_1_4 = "FindFirstFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


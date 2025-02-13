rule Ransom_MSIL_Azazel_DA_2147788053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Azazel.DA!MTB"
        threat_id = "2147788053"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azazel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "azazel is the best oo yeah bitch" ascii //weight: 1
        $x_1_2 = ".azazel" ascii //weight: 1
        $x_1_3 = "kk.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


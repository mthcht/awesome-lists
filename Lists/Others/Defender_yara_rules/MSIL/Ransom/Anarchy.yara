rule Ransom_MSIL_Anarchy_DA_2147931358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Anarchy.DA!MTB"
        threat_id = "2147931358"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Anarchy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All of your files got encrypted" ascii //weight: 1
        $x_1_2 = "*_anarchy" ascii //weight: 1
        $x_1_3 = "Pay a ransom" ascii //weight: 1
        $x_1_4 = "EncryptFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


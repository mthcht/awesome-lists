rule Ransom_MSIL_BlackWorld_DA_2147767071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BlackWorld.DA!MTB"
        threat_id = "2147767071"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackWorld"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Black World Ransomware.exe" ascii //weight: 1
        $x_1_2 = "Black_World_Ransomware.Properties" ascii //weight: 1
        $x_1_3 = "Black World Ransomware.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


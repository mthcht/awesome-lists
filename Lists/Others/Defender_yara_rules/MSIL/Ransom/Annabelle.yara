rule Ransom_MSIL_Annabelle_DA_2147779083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Annabelle.DA!MTB"
        threat_id = "2147779083"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Annabelle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fileEncrypted" ascii //weight: 1
        $x_1_2 = "bytesToBeEncrypted" ascii //weight: 1
        $x_1_3 = "FridayProject.Properties" ascii //weight: 1
        $x_1_4 = "GetTempPath" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Annabelle_DA_2147779083_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Annabelle.DA!MTB"
        threat_id = "2147779083"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Annabelle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Annabelle.Resources.resources" ascii //weight: 1
        $x_1_2 = "Annabelle.exe" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "GetLogicalDrives" ascii //weight: 1
        $x_1_5 = "ActionEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


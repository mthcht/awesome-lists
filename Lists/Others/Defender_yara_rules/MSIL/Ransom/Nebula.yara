rule Ransom_MSIL_Nebula_SPR_2147948690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Nebula.SPR!MTB"
        threat_id = "2147948690"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nebula"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "NebulaRun.Properties.Resources" wide //weight: 2
        $x_1_2 = "delself.bat" wide //weight: 1
        $x_1_3 = "Nebula Decryptor" wide //weight: 1
        $x_1_4 = "NebulaRun.nebula.png" wide //weight: 1
        $x_1_5 = ".nbl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Nebula_YBE_2147959141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Nebula.YBE!MTB"
        threat_id = "2147959141"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nebula"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Files Are Encrypted By Nebula" ascii //weight: 1
        $x_1_2 = "Knowledge Is Encrypted" ascii //weight: 1
        $x_1_3 = "You Have To Pay" ascii //weight: 1
        $x_1_4 = "Permanent Data Loss" ascii //weight: 1
        $x_1_5 = "Files To Locked Up" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


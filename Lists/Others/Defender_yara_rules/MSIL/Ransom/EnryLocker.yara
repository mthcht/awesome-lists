rule Ransom_MSIL_EnryLocker_PAA_2147787141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/EnryLocker.PAA!MTB"
        threat_id = "2147787141"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EnryLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RansomeWare.Properties.Resources.resources" ascii //weight: 1
        $x_1_2 = "RansomeWare.pdb" ascii //weight: 1
        $x_1_3 = "Your files have been encrypted" wide //weight: 1
        $x_1_4 = ".henry" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_MSIL_SamSam_A_2147731337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SamSam.A"
        threat_id = "2147731337"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SamSam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\obj\\Release\\ss2.pdb" ascii //weight: 1
        $x_1_2 = "1HbJu2kL4xDNK1L9YUDkJnqh3yiC119YM2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


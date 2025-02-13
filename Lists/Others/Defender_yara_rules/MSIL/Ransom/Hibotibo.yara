rule Ransom_MSIL_Hibotibo_AA_2147905575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hibotibo.AA!MTB"
        threat_id = "2147905575"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hibotibo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your important files and documents have been encrypted by us" ascii //weight: 1
        $x_1_2 = "Hitobito" ascii //weight: 1
        $x_1_3 = "willing to pay for your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


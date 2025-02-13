rule Ransom_MSIL_Revenge_DA_2147773474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Revenge.DA!MTB"
        threat_id = "2147773474"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Revenge"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files gone" ascii //weight: 1
        $x_1_2 = "Ransomeware" ascii //weight: 1
        $x_1_3 = "ReadToRestore.txt" ascii //weight: 1
        $x_1_4 = ".REVENGE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


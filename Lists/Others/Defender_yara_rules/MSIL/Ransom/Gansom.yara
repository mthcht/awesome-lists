rule Ransom_MSIL_Gansom_AA_2147749888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Gansom.AA!MSR"
        threat_id = "2147749888"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gansom"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "repos\\Ransomware\\Ransomware\\obj\\Debug\\Ransomware.pdb" ascii //weight: 1
        $x_1_2 = "Ransomware.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


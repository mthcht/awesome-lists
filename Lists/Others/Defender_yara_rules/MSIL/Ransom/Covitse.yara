rule Ransom_MSIL_Covitse_PI_2147751513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Covitse.PI!MSR"
        threat_id = "2147751513"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Covitse"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[COVID-19 RANSOMWARE]" wide //weight: 1
        $x_1_2 = "your been infected with Lansom by COVID-19 Ransomware." wide //weight: 1
        $x_1_3 = "\\COVID-19.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_MSIL_Jerwica_AMTB_2147966087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Jerwica!AMTB"
        threat_id = "2147966087"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jerwica"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JerwicaRansom.pdb" ascii //weight: 2
        $x_1_2 = "get_victim_id" ascii //weight: 1
        $x_1_3 = "JerwicaRansom_ProcessedByFody " ascii //weight: 1
        $x_1_4 = "jerwica_infected.txt " ascii //weight: 1
        $x_1_5 = ".jerwica" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


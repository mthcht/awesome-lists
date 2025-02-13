rule Ransom_MSIL_Istola_A_2147726720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Istola.A"
        threat_id = "2147726720"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Istola"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RansomBuilder1" ascii //weight: 2
        $x_2_2 = "Bir seyleri yanlis yapiyorsun" wide //weight: 2
        $x_2_3 = "TurkHackTeam.Org" wide //weight: 2
        $x_4_4 = "RansomBuilder1.0\\RansomBuilder1.0\\obj\\Debug\\RansomBuilder1.0.pdb" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}


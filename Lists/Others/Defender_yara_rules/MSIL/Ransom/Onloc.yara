rule Ransom_MSIL_Onloc_2147724451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Onloc"
        threat_id = "2147724451"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Onloc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = ">>> Hacked By Lock0n Ransomware ! <<<" wide //weight: 5
        $x_5_2 = "1EhHaeQ5x8Q4wF62QwqRUfoFrbYo2PLR7c" wide //weight: 5
        $x_5_3 = "Projets\\Lockon Ransomware\\Lockon Ransomware\\obj\\Debug\\Lockon Ransomware.pdb" ascii //weight: 5
        $x_5_4 = "Lockon Ransomware.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


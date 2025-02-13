rule Ransom_MSIL_Cryptrat_A_2147721823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptrat.A!bit"
        threat_id = "2147721823"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptrat"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ftp://www.lolaail." wide //weight: 2
        $x_1_2 = "encrypt with our 4rw5w crypt virus" ascii //weight: 1
        $x_1_3 = "\\4rw5wDecryptor\\obj\\Debug\\4rw5wDecryptor.pdb" ascii //weight: 1
        $x_1_4 = "*.4rwcry4w" wide //weight: 1
        $x_1_5 = ".4rnkey" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


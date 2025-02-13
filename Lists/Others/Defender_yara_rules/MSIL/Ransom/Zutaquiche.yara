rule Ransom_MSIL_Zutaquiche_A_2147707804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Zutaquiche.A"
        threat_id = "2147707804"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zutaquiche"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " ID -" ascii //weight: 1
        $x_1_2 = ".block" ascii //weight: 1
        $x_1_3 = {2e 00 64 00 6f 00 63 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 78 00 6c 00 73 00}  //weight: 1, accuracy: Low
        $x_3_4 = "email yagababushka@yahoo.com" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


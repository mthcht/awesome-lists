rule Ransom_MSIL_Kuhuqubata_A_2147707676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Kuhuqubata.A"
        threat_id = "2147707676"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kuhuqubata"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encryptDirectory" ascii //weight: 1
        $x_1_2 = "See you in my ICQ" wide //weight: 1
        $x_1_3 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 00 0b 2e 00 64 00 6f 00 63 00 78}  //weight: 1, accuracy: High
        $x_2_4 = "\\Desktop\\README!!!.txt" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


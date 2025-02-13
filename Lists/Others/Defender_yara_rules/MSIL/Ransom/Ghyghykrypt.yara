rule Ransom_MSIL_Ghyghykrypt_A_2147721675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Ghyghykrypt.A"
        threat_id = "2147721675"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ghyghykrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Tengo malas noticias" wide //weight: 2
        $x_1_2 = "READ_IT.txt" wide //weight: 1
        $x_1_3 = "\\Desktop\\pass.txt" wide //weight: 1
        $x_1_4 = ".thatMoment" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


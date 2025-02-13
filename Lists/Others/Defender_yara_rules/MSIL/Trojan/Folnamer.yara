rule Trojan_MSIL_Folnamer_A_2147696422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Folnamer.A"
        threat_id = "2147696422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Folnamer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rm9sZGVyTmFtZVxmaWxlLmV4ZSI=" ascii //weight: 1
        $x_1_2 = "Rm9sZGVyTmFtZVxtZWx0LmJhdA==" ascii //weight: 1
        $x_1_3 = "Rm9sZGVyTmFtZVxtYXRhMi5iYXQ=" ascii //weight: 1
        $x_1_4 = "Rm9sZGVyTmFtZVxNaWNyb3NvZnQtQWNjZXNzLTIwMTMuYmF0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


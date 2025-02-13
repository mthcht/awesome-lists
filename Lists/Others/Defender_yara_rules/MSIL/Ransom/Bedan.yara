rule Ransom_MSIL_Bedan_A_2147719160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Bedan.A"
        threat_id = "2147719160"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bedan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files were encrypted by the BadEncript ransomware!" wide //weight: 1
        $x_1_2 = "to get the password and decrypt" wide //weight: 1
        $x_1_3 = "unlock your files you need to pay" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


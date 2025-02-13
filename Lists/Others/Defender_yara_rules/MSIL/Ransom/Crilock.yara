rule Ransom_MSIL_Crilock_A_2147684886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crilock.A"
        threat_id = "2147684886"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crilock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your important files on this computer were encrypted: photos, videos, documents," ascii //weight: 1
        $x_1_2 = {79 6f 75 20 6e 65 65 64 20 74 6f 20 70 61 79 20 33 30 30 20 55 53 44 20 2f 20 45 55 52 20 2f 20 73 69 6d 69 6c 61 72 20 61 6d 6f 75 6e 74 20 69 6e 20 42 69 74 63 6f 69 6e 2e 0a 0a 43 6c 69 63}  //weight: 1, accuracy: High
        $x_2_3 = {2e 72 65 73 6f 75 72 63 65 73 00 6d 73 75 6e 65 74 2e 66 72 6d 35 2e 72 65 73 6f 75 72 63 65 73 00 6d 73 75 6e 65 74 2e 66 72 6d 32 2e 72 65 73}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}


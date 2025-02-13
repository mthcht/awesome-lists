rule Backdoor_MSIL_Reverto_A_2147641139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Reverto.A"
        threat_id = "2147641139"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reverto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe d6 84 11 c2 80 6f 91 13 ef 83 cd 31 5a 08 b4 f8 3a 85 da a6 93 c4 ed 3a 46 95 50 b6 b1 82 ce a4 4b 08 9f 8c 10 4e 48 8a 9a b5 2d df 70 47 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


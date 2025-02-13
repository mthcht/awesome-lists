rule Ransom_MSIL_Spooky_DD_2147741934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Spooky.DD"
        threat_id = "2147741934"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spooky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 73 65 72 73 [0-16] 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 43 72 79 62 6c 65 [0-5] 5c 43 72 79 62 6c 65 [0-5] 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 72 79 62 6c 65 [0-5] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = {63 72 79 62 6c 65 [0-5] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


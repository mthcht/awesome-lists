rule Ransom_MSIL_Pykaro_A_2147722448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Pykaro.A"
        threat_id = "2147722448"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pykaro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 5b 33 4e 11 04 1f 5d 6f cd 00 00 0a 17 2c b7}  //weight: 1, accuracy: High
        $x_1_2 = {6b 61 72 6f 2e 65 78 65 00 6b 61 72 6f 00 3c 4d 6f 64 75 6c 65 3e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


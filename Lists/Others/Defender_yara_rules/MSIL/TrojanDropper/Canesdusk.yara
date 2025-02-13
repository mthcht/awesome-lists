rule TrojanDropper_MSIL_Canesdusk_A_2147641931_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Canesdusk.A"
        threat_id = "2147641931"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Canesdusk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0c 02 02 8e b7 17 da 91 1f 70 61 0d 02 8e b7 17 d6 8d 1b 00 00 01 0b 16 02 8e b7 17 da 13 06 13 05 2b 2d 07 11 05 02 11 05 91 09 61 08 11 04}  //weight: 10, accuracy: High
        $x_1_2 = {64 65 63 72 79 70 74 00 6d 65 73 73 61 67 65 00 70 61 73 73 77 6f 72 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


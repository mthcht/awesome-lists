rule TrojanDropper_MSIL_Stetsorve_A_2147641956_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Stetsorve.A"
        threat_id = "2147641956"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stetsorve"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 1c 28 06 00 00 0a 72 01 00 00 70 06 20 10 27 00 00 20 3f 42 0f 00 6f 07 00 00 0a 13 0b 12 0b 28 08 00 00 0a 72 05 00 00 70 28 09 00 00 0a 0d 08}  //weight: 1, accuracy: High
        $x_1_2 = {2e 65 78 65 00 5f 4d 61 69 6e 00 43 4f 4c 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


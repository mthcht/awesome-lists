rule VirTool_MSIL_Darius_B_2147853073_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Darius.B"
        threat_id = "2147853073"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darius"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 12 00 28 4b 00 00 0a 2d 11}  //weight: 1, accuracy: High
        $x_1_2 = {28 6c 00 00 06 0b 02 17 9a 28 6d 00 00 06 0c}  //weight: 1, accuracy: High
        $x_1_3 = {28 70 00 00 06 13 06 07 08 11 04 11 05 11 06 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


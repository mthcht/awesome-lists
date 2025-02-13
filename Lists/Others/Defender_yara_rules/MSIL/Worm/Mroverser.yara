rule Worm_MSIL_Mroverser_A_2147697417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Mroverser.A"
        threat_id = "2147697417"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mroverser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {2e 65 78 65 00 4d 6f 2d 53 65 72 76 65 72 00 3c 4d 6f 64 75 6c 65 3e}  //weight: 4, accuracy: High
        $x_1_2 = {73 65 72 76 65 72 55 72 6c 00 55 70 6c 6f 61 64 52 65 70 6f 72 74}  //weight: 1, accuracy: High
        $x_1_3 = "4rc+RUBiB6c/ZMXTqsaAIxLBm" wide //weight: 1
        $x_1_4 = "R7TYj9WXMGK6QWP6+AKdymAznk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


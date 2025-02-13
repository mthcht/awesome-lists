rule Worm_MSIL_Lime_A_2147727181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Lime.A!bit"
        threat_id = "2147727181"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lime"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lime_Worm" wide //weight: 1
        $x_1_2 = "Module Nervousness" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


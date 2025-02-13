rule HackTool_MSIL_Grobo_2147687974_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Grobo"
        threat_id = "2147687974"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Grobo"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 00 72 00 6f 00 77 00 42 00 6f 00 74 00 [0-16] 73 00 6b 00 79 00 70 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 73 70 61 6d 00 67 65 74 5f 73 70 61 6d 00 73 65 74 5f 73 70 61 6d 00 5f 73 65 6e 64 61 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


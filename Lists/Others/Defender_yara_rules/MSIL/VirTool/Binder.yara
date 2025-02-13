rule VirTool_MSIL_Binder_B_2147633329_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Binder.B"
        threat_id = "2147633329"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Binder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 56 4b 69 6c 6c 65 72 73 69 6e 42 69 6e 64 65 72 00 41 56 4b 69 6c 6c 65 72 73 77 6f 42 69 6e 64 65 72 00 69 6e 6a 65 63 74 69 6f 6e 77 6f 62 69 6e 64 65 72 00 69 6e 6a 65 63 74 69 6f 6e 69 6e 62 69 6e 64 65 72 00 6d 73 67 62 6f 78 77 69 74 68 6f 75 74}  //weight: 1, accuracy: High
        $x_1_2 = {41 6e 74 69 56 69 72 74 75 61 6c 50 43 00 41 6e 74 69 56 69 72 74 75 61 6c 42 6f 78 00 41 6e 74 69 56 6d 57 61 72 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


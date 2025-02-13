rule HackTool_MSIL_Boilod_C_2147724988_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Boilod.C!bit"
        threat_id = "2147724988"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Boilod"
        severity = "High"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 69 66 2d 74 68 69 73 2d 61 73 73 65 6d 62 6c 79 2d 77 61 73 2d 66 6f 75 6e 64 2d 62 65 69 6e 67 2d 75 73 65 64 2d 6d 61 6c 69 63 69 6f 75 73 6c 79 2d 2e 2d 54 68 69 73 2d 66 69 6c 65 2d 77 61 73 2d 62 75 69 6c 74 2d 75 73 69 6e 67 2d 49 6e 76 69 73 69 62 6c 65 2d 4d 6f 64 65 00 49 6d 6d 69 6e 65 6e 74 2d 4d 6f 6e 69 74 6f 72 2d 43 6c 69 65 6e 74 2d 57 61 74 65 72 6d 61 72 6b}  //weight: 1, accuracy: High
        $x_1_2 = {41 70 70 44 6f 6d 61 69 6e 00 67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 76 65 6e 5a 69 70 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 2e 4c 5a 4d 41 00 44 65 63 6f 6d 70 72 65 73 73}  //weight: 1, accuracy: High
        $x_1_4 = {47 65 74 45 6e 74 72 79 41 73 73 65 6d 62 6c 79 00 47 65 74 4d 65 74 68 6f 64 00 4d 65 74 68 6f 64 49 6e 66 6f 00 4d 65 74 68 6f 64 42 61 73 65 00 49 6e 76 6f 6b 65 00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


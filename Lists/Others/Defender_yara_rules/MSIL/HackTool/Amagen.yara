rule HackTool_MSIL_Amagen_A_2147641075_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Amagen.A"
        threat_id = "2147641075"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amagen"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Amazon Receipt Generator" ascii //weight: 1
        $x_1_2 = {50 6c 65 61 73 65 20 6d 61 6b 65 20 73 75 72 65 20 74 6f 20 76 69 73 69 74 20 6f 75 72 20 73 69 74 65 20 61 6e 64 20 73 69 67 6e 20 75 70 20 66 6f 72 20 6d 6f 72 65 [0-4] 62 6f 74 73 20 6c 69 6b 65 20 74 68 69 73 20 6f 6e 65}  //weight: 1, accuracy: Low
        $x_1_3 = "The order number is the number that will be generated" ascii //weight: 1
        $x_1_4 = "Botting World" ascii //weight: 1
        $x_1_5 = "System.Runtime.CompilerServices" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


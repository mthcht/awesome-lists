rule VirTool_MSIL_Sharpldr_A_2147945276_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Sharpldr.A"
        threat_id = "2147945276"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sharpldr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 65 6d 65 6e 74 6f 72 2e 65 78 65 00 6d 73 63 6f 72 6c 69 62 00 53 75 70 70 72 65 73 73}  //weight: 1, accuracy: High
        $x_1_2 = {8f e2 81 ae e2 80 8e e2 80 aa e2 80 ab e2 80 8c e2 80 8e e2 80 ac e2 80 8e e2}  //weight: 1, accuracy: High
        $x_1_3 = {81 ab e2 80 ad e2 81 ae e2 80 ad e2 81 aa e2 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


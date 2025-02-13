rule VirTool_MSIL_Peckpai_A_2147711667_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Peckpai.A"
        threat_id = "2147711667"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Peckpai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 74 73 65 6c 66 43 72 79 70 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 79 61 73 73 00}  //weight: 1, accuracy: High
        $x_10_3 = {2e 72 65 73 6f 75 72 63 65 73 [0-96] 47 69 00 6e 00 6a 00 [0-112] 47 70 00 61 00 79 00}  //weight: 10, accuracy: Low
        $x_1_4 = "Resource.Mainentry" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


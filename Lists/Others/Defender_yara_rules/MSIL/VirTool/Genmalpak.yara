rule VirTool_MSIL_Genmalpak_B_2147711780_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Genmalpak.B"
        threat_id = "2147711780"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genmalpak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 11 0a 08 11 0a 91 11 05 11 0a 09 5d 91 61 9c 11 0a 17 d6 13 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


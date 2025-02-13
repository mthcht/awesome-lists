rule VirTool_MSIL_Ranos_A_2147685538_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Ranos.A"
        threat_id = "2147685538"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ranos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2fd328bf-397b-4e96-9842-85937cd2d27a" ascii //weight: 1
        $x_1_2 = {2f 04 b1 03 3f 04 30 01 ac 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


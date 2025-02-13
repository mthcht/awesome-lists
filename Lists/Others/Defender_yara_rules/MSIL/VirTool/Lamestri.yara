rule VirTool_MSIL_Lamestri_2147705869_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lamestri"
        threat_id = "2147705869"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lamestri"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\users\\administrator\\desktop\\cryptex\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


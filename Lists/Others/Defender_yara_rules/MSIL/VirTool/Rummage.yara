rule VirTool_MSIL_Rummage_2147681502_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Rummage"
        threat_id = "2147681502"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rummage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rummage is licensed to  (issue 0) for use with ." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


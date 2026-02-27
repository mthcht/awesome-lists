rule HackTool_MSIL_Stracciatella_AMTB_2147963764_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Stracciatella!AMTB"
        threat_id = "2147963764"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stracciatella"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DisableScriptLoggingTechnique1" ascii //weight: 1
        $x_1_2 = "DisableAmsiTechnique" ascii //weight: 1
        $x_1_3 = "Stracciatella.pdb" ascii //weight: 1
        $x_1_4 = "Powershell runspace with AMSI and Script Block Logging disabled." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule HackTool_MSIL_Elevate_SA_2147747936_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Elevate.SA"
        threat_id = "2147747936"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Elevate"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BypassUAC" ascii //weight: 1
        $x_1_2 = "Attempting Bypass" wide //weight: 1
        $x_1_3 = "Administrator privileges required" wide //weight: 1
        $x_1_4 = "DisableAllPrivileges" ascii //weight: 1
        $x_5_5 = "Tokenvator.pdb" ascii //weight: 5
        $x_1_6 = "[!] Anti-Virus" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


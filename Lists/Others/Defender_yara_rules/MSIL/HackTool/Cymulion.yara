rule HackTool_MSIL_Cymulion_SBR_2147772512_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Cymulion.SBR!MSR"
        threat_id = "2147772512"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cymulion"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c schtasks /Run /TN \"\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" wide //weight: 1
        $x_1_2 = "edr_attacks_path" wide //weight: 1
        $x_1_3 = "UACbypass" wide //weight: 1
        $x_1_4 = "LogProvider.dll" wide //weight: 1
        $x_1_5 = "dllHijacking.pdb" ascii //weight: 1
        $x_1_6 = "CymulateDllHijack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


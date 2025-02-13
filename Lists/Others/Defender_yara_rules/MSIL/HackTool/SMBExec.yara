rule HackTool_MSIL_SMBExec_SK_2147899038_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/SMBExec.SK!MTB"
        threat_id = "2147899038"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SMBExec"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$344ee55a-4e32-46f2-a003-69ad52b55945" ascii //weight: 1
        $x_1_2 = "SharpInvoke-SMBExec\\obj\\Release\\SMBBBB.pdb" ascii //weight: 1
        $x_1_3 = "SMBBBB.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


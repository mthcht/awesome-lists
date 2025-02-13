rule HackTool_MSIL_PassViewer_A_2147740857_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/PassViewer.A"
        threat_id = "2147740857"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PassViewer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Doctorpol.My.Resources" ascii //weight: 1
        $x_1_2 = "DoEvilWork" ascii //weight: 1
        $x_1_3 = "Doctorpol.exe" ascii //weight: 1
        $x_1_4 = "Debug\\Doctorpol.pdb" ascii //weight: 1
        $x_1_5 = "Doctorpol.Resources" wide //weight: 1
        $x_1_6 = "TVqQ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


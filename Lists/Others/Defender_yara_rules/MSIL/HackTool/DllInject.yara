rule HackTool_MSIL_DllInject_A_2147755889_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/DllInject.A!MTB"
        threat_id = "2147755889"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ayy Hook.exe" wide //weight: 1
        $x_1_2 = "Ayy Hook.pdb" ascii //weight: 1
        $x_1_3 = "\\AyyHook\\cheat.dll" wide //weight: 1
        $x_1_4 = "Ayy_Hook.Properties.Resources" wide //weight: 1
        $x_1_5 = "Injecting, Please wait..." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


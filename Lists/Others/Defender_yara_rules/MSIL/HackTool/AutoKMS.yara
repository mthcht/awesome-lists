rule HackTool_MSIL_AutoKMS_I_2147743522_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/AutoKMS.I!MTB"
        threat_id = "2147743522"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AutoKMS"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\TunMirror\\obj\\Release\\TunMirror.pdb" ascii //weight: 10
        $x_1_2 = "$6a1f4016-f16e-41bc-80fb-0642c8a34893" ascii //weight: 1
        $x_1_3 = "$70f17a4e-cc8c-44a7-99c2-e3a0e2554758" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_MSIL_AutoKMS_AB_2147811739_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/AutoKMS.AB!MTB"
        threat_id = "2147811739"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AutoKMS"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsKmsClient" ascii //weight: 1
        $x_1_2 = "KMSELDI.pdb" ascii //weight: 1
        $x_1_3 = "Activation GUI for KMS Host" ascii //weight: 1
        $x_1_4 = "set_ActivateButton" ascii //weight: 1
        $x_1_5 = "Run KMS Emulator" ascii //weight: 1
        $x_1_6 = "Windows Activated" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


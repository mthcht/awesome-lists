rule Backdoor_MSIL_Ratgen_GA_2147820150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Ratgen.GA!MTB"
        threat_id = "2147820150"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ratgen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PassGrabber" ascii //weight: 1
        $x_1_2 = "Debugger Detected" ascii //weight: 1
        $x_1_3 = "unregistered version of Eziriz's \".NET Reactor\"!" wide //weight: 1
        $x_1_4 = "file:///" wide //weight: 1
        $x_1_5 = "Location" wide //weight: 1
        $x_1_6 = "ResourceA" wide //weight: 1
        $x_1_7 = "Virtual" wide //weight: 1
        $x_1_8 = "Write" wide //weight: 1
        $x_1_9 = "Memory" wide //weight: 1
        $x_1_10 = "Protect" wide //weight: 1
        $x_1_11 = "32.dll" wide //weight: 1
        $x_1_12 = "{11111-22222-30001-00001}" wide //weight: 1
        $x_1_13 = "{11111-22222-40001-00001}" wide //weight: 1
        $x_1_14 = "GetDelegateForFunctionPointer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


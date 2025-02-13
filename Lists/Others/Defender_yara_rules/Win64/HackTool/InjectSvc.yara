rule HackTool_Win64_InjectSvc_A_2147740603_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/InjectSvc.A"
        threat_id = "2147740603"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "InjectSvc"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "creating remote thread - FreeLibrary" ascii //weight: 1
        $x_1_2 = "InjectHook returned %d" ascii //weight: 1
        $x_1_3 = "adjusted SeDebugPrivilige" ascii //weight: 1
        $x_1_4 = "opening process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


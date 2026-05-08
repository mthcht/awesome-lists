rule HackTool_Win64_SafetyKatz_VGL_2147968803_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/SafetyKatz.VGL!MTB"
        threat_id = "2147968803"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "SafetyKatz"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SafetyKatz.exe" wide //weight: 1
        $x_1_2 = "$8347e81b-89fc-42a9-b22c-f59a6a572dec" ascii //weight: 1
        $x_1_3 = "ParameterizedThreadStart" ascii //weight: 1
        $x_1_4 = "FileAccess" ascii //weight: 1
        $x_1_5 = "WrapNonExceptionThrows" ascii //weight: 1
        $x_1_6 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


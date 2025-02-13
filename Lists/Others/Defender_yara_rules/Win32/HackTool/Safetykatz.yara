rule HackTool_Win32_Safetykatz_A_2147729504_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Safetykatz.A"
        threat_id = "2147729504"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Safetykatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "zL17fBNV+jg8aVJIoWUCNFC1apCoXUEsBrW1gJl2AhNIaJVbVZAqiLig1pJAFVQwLRKP47ourrq6rndZLwu6KlBWbCm9cWsp" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


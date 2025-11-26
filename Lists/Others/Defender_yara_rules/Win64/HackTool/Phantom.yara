rule HackTool_Win64_Phantom_AP_2147958300_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Phantom.AP!AMTB"
        threat_id = "2147958300"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Phantom"
        severity = "High"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attempting to detect PID from Service Manager" ascii //weight: 1
        $x_1_2 = "Process Integrity Level is not high." ascii //weight: 1
        $x_1_3 = "Using Technique-1 for killing threads" ascii //weight: 1
        $x_1_4 = "Event Log service PID detected" ascii //weight: 1
        $x_1_5 = "Thread %d is detected but kill failed." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


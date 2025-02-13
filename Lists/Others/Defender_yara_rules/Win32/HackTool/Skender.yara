rule HackTool_Win32_Skender_2147686752_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Skender"
        threat_id = "2147686752"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Skender"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SKYPE4COMLib" ascii //weight: 1
        $x_1_2 = "kypesender.ru/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


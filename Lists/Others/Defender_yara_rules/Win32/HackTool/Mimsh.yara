rule HackTool_Win32_Mimsh_2147690317_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimsh"
        threat_id = "2147690317"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimsh"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/clymb3r/PowerShell/blob/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1" ascii //weight: 1
        $x_1_2 = "tinyurl.com/mnq854e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


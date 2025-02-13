rule VirTool_Win32_SvcStealer_A_2147915056_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SvcStealer.A!MTB"
        threat_id = "2147915056"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SvcStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GDUuHQoGE0krKw8VGg4GFzUkCxkEHw5UIR0ZJgUEMTM4HQoZKEkyGQ4AFw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


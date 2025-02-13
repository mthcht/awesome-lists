rule VirTool_Win32_Kackperk_A_2147767614_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Kackperk.A!MTB"
        threat_id = "2147767614"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Kackperk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SSH_RevShell/client/client.go" ascii //weight: 1
        $x_1_2 = "SSH_RevShell/client/core/shell.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


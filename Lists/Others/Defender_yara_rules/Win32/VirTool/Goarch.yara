rule VirTool_Win32_Goarch_A_2147755221_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Goarch.A!MTB"
        threat_id = "2147755221"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Goarch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "go-shellcode/shellcode_windows.go" ascii //weight: 1
        $x_1_2 = {48 8b 89 00 00 00 00 48 3b 61 10 0f 86 98 01 00 00 48 83 ec 70 48 89 6c 24 68 48 8d 6c 24 68 48 8d 05 49 04 04 00 48 89 44 24 50 48 8d 05 f5 30 01 00 48 89 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


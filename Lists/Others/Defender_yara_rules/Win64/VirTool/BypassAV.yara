rule VirTool_Win64_BypassAV_C_2147928577_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/BypassAV.C"
        threat_id = "2147928577"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassAV"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bypassEDR-AV/syscall.go" ascii //weight: 1
        $x_1_2 = "ReturnShellcode" ascii //weight: 1
        $x_1_3 = "LoadResource" ascii //weight: 1
        $x_1_4 = "MAKEINTRESOURCE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win64_Clkndag_A_2147912949_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Clkndag.A"
        threat_id = "2147912949"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Clkndag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.getCurrentUser" ascii //weight: 1
        $x_1_2 = "CloakNDaggerC2" ascii //weight: 1
        $x_1_3 = "runCommand" ascii //weight: 1
        $x_1_4 = "syscall.GetCurrentProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


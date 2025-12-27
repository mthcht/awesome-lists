rule VirTool_Win32_SuspPowershellExec_B_2147958111_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowershellExec.B"
        threat_id = "2147958111"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowershellExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VwByAGkAdABlAC0ASABvAHMAdAAgACIA" wide //weight: 1
        $x_1_2 = "AGkAbAAgAHMAdAB1AGYAZgAgAGgAZQByAGUAIgA=" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = " -window hidden -e" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


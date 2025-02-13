rule HackTool_Win32_PplFault_A_2147846558_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PplFault.A"
        threat_id = "2147846558"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PplFault"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CfRegisterSyncRoot" ascii //weight: 1
        $x_1_2 = "MiniDumpWriteDump" ascii //weight: 1
        $x_1_3 = {48 87 c9 c7 ?? ?? 48 87 d2 4d c7 ?? ?? 87 c0 4d 87 66 c7 ?? ?? c9}  //weight: 1, accuracy: Low
        $x_10_4 = {4c 8b e8 c7 44 24 ?? d3 c0 ad 1b c7 44 24 ?? ef be ad de}  //weight: 10, accuracy: Low
        $x_10_5 = {c7 03 d3 c0 ad 1b c7 43 04 ef be ad de}  //weight: 10, accuracy: High
        $x_10_6 = {23 65 9c 11 ?? ?? ?? 7b 40 6b 44 ?? ?? ?? b0 e3 e0 30}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_PplFault_B_2147846820_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PplFault.B"
        threat_id = "2147846820"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PplFault"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CfRegisterSyncRoot" ascii //weight: 1
        $x_1_2 = "MiniDumpWriteDump" ascii //weight: 1
        $x_1_3 = "\\Device\\PhysicalMemory" ascii //weight: 1
        $x_10_4 = {c7 03 d3 c0 ad 1b [0-16] c7 43 04 ef be ad de}  //weight: 10, accuracy: Low
        $x_10_5 = {48 87 c9 41 b8 3c 00 00 00 48 87 d2 4d [0-16] 87 c0 4d 87}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


rule HackTool_Win32_PossibleActiveDirectoryNtdsDumping_A_2147950479_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PossibleActiveDirectoryNtdsDumping.A"
        threat_id = "2147950479"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PossibleActiveDirectoryNtdsDumping"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ntdsutil" wide //weight: 1
        $x_1_2 = "activate instance ntds" wide //weight: 1
        $x_1_3 = "create full" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


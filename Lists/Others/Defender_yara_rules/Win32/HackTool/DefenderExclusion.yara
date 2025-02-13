rule HackTool_Win32_DefenderExclusion_A_2147813254_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DefenderExclusion.A"
        threat_id = "2147813254"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DefenderExclusion"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe" wide //weight: 1
        $x_1_2 = "add" wide //weight: 1
        $x_1_3 = "hklm\\software\\microsoft\\windows defender\\exclusions\\paths" wide //weight: 1
        $x_1_4 = "/f /t reg_dword /v" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


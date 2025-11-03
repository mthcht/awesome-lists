rule VirTool_Win32_DefenderTamper_F_2147956565_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DefenderTamper.F"
        threat_id = "2147956565"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DefenderTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5c 00 49 00 4f 00 62 00 69 00 74 00 55 00 6e 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_2_2 = " /Delete " wide //weight: 2
        $x_2_3 = " /Advanced " wide //weight: 2
        $x_1_4 = "C:\\ProgramData\\Microsoft\\Windows Defender" wide //weight: 1
        $x_1_5 = "C:\\Program Files\\Windows Defender" wide //weight: 1
        $x_1_6 = "C:\\Program Files (x86)\\Windows Defender" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


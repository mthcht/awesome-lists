rule VirTool_Win32_SuspDenoExec_A_2147981499_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspDenoExec.A"
        threat_id = "2147981499"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDenoExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5c 00 64 00 65 00 6e 00 6f 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "run -A https://" wide //weight: 1
        $x_1_3 = "run -A http://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule VirTool_Win32_SuspMsiExec_A_2147949206_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspMsiExec.A"
        threat_id = "2147949206"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMsiExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = " http://" wide //weight: 1
        $x_1_3 = " https://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule VirTool_Win32_SuspMshtaExec_A_2147949544_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspMshtaExec.A"
        threat_id = "2147949544"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMshtaExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = " http://" wide //weight: 1
        $x_1_3 = " https://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


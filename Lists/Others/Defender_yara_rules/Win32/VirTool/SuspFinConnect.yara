rule VirTool_Win32_SuspFinConnect_A_2147981185_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspFinConnect.A"
        threat_id = "2147981185"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspFinConnect"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 66 00 69 00 6e 00 67 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = {66 00 69 00 6e 00 67 00 65 00 72 00 20 00 [0-48] 40 00 [0-64] 2e 00 2b 02 02 00}  //weight: 1, accuracy: Low
        $x_1_3 = {66 00 69 00 6e 00 67 00 65 00 72 00 2e 00 65 00 78 00 65 00 20 00 [0-48] 40 00 [0-64] 2e 00 2b 02 02 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


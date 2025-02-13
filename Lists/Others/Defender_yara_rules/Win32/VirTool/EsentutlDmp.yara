rule VirTool_Win32_EsentutlDmp_A_2147796983_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/EsentutlDmp.A"
        threat_id = "2147796983"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "EsentutlDmp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\esentutl.exe" wide //weight: 2
        $x_1_2 = {73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 [0-2] 63 00 6f 00 6e 00 66 00 69 00 67 00 [0-2] 53 00 41 00 4d 00 20 00}  //weight: 1, accuracy: Low
        $x_1_3 = {73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 [0-2] 63 00 6f 00 6e 00 66 00 69 00 67 00 [0-2] 53 00 59 00 53 00 54 00 45 00 4d 00 20 00}  //weight: 1, accuracy: Low
        $x_1_4 = {73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 [0-2] 63 00 6f 00 6e 00 66 00 69 00 67 00 [0-2] 53 00 45 00 43 00 55 00 52 00 49 00 54 00 59 00 20 00}  //weight: 1, accuracy: Low
        $x_1_5 = " /y " wide //weight: 1
        $x_1_6 = " /d " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


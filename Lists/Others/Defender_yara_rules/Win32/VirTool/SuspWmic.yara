rule VirTool_Win32_SuspWmic_A_2147849832_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspWmic.A!cbl4"
        threat_id = "2147849832"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWmic"
        severity = "Critical"
        info = "cbl4: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 57 00 4d 00 49 00 43 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /node:" wide //weight: 1
        $x_1_3 = " /privileges:enable " wide //weight: 1
        $x_1_4 = " /output:STDOUT " wide //weight: 1
        $x_1_5 = {20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 63 00 61 00 6c 00 6c 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 [0-8] 63 00 6d 00 64 00 [0-8] 20 00 2f 00 63 00 20 00 [0-8] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-8] 20 00 2d 00 46 00 69 00 6c 00 65 00 20 00 [0-8] 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 [0-32] 2e 00 70 00 73 00 31 00 20 00 3e 00 20 00}  //weight: 1, accuracy: Low
        $x_1_6 = ".log 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


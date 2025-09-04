rule VirTool_Win32_DumpLsassProc_A_2147777546_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DumpLsassProc.A"
        threat_id = "2147777546"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsassProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "\\rundll32.exe" wide //weight: 1
        $x_1_3 = {5c 00 63 00 6f 00 6d 00 73 00 76 00 63 00 73 00 2e 00 64 00 6c 00 6c 00 [0-8] 4d 00 69 00 6e 00 69 00 44 00 75 00 6d 00 70 00 20 00 28 00 47 00 65 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 6c 00 73 00 61 00 73 00 73 00 29 00 2e 00 49 00 64 00 20 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 63 00 6f 00 6d 00 73 00 76 00 63 00 73 00 2e 00 64 00 6c 00 6c 00 [0-255] 32 00 34 00 [0-48] 20 00 28 00 47 00 65 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 6c 00 73 00 61 00 73 00 73 00 29 00 2e 00 49 00 64 00}  //weight: 1, accuracy: Low
        $x_1_5 = {54 00 65 00 6d 00 70 00 5c 00 [0-240] 2e 00 64 00 6d 00 70 00 20 00 66 00 75 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 [0-255] 66 00 75 00 6c 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_DumpLsassProc_B_2147777547_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DumpLsassProc.B"
        threat_id = "2147777547"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsassProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "tasklist /fi " wide //weight: 1
        $x_1_3 = "Imagename eq lsass.exe" wide //weight: 1
        $x_1_4 = {66 00 69 00 6e 00 64 00 [0-8] 6c 00 73 00 61 00 73 00 73 00}  //weight: 1, accuracy: Low
        $x_1_5 = "rundll32.exe" wide //weight: 1
        $x_1_6 = {5c 00 63 00 6f 00 6d 00 73 00 76 00 63 00 73 00 2e 00 64 00 6c 00 6c 00 [0-8] 4d 00 69 00 6e 00 69 00 44 00 75 00 6d 00 70 00 20 00}  //weight: 1, accuracy: Low
        $x_1_7 = {54 00 65 00 6d 00 70 00 5c 00 [0-240] 2e 00 64 00 6d 00 70 00 20 00 66 00 75 00 6c 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DumpLsassProc_R1_2147809900_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DumpLsassProc.R1"
        threat_id = "2147809900"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsassProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "rdrleakdiag.exe" wide //weight: 1
        $x_1_3 = {2f 00 70 00 [0-8] 28 00 47 00 65 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 6c 00 73 00 61 00 73 00 73 00 29 00 2e 00 49 00 64 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DumpLsassProc_R2_2147809901_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DumpLsassProc.R2"
        threat_id = "2147809901"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsassProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "tasklist /fi " wide //weight: 1
        $x_1_3 = "Imagename eq lsass.exe" wide //weight: 1
        $x_1_4 = "rdrleakdiag.exe" wide //weight: 1
        $x_1_5 = "/p" wide //weight: 1
        $x_1_6 = {66 00 69 00 6e 00 64 00 [0-8] 6c 00 73 00 61 00 73 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DumpLsassProc_C_2147850840_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DumpLsassProc.C"
        threat_id = "2147850840"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsassProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "tasklist /fi " wide //weight: 1
        $x_1_3 = "imagename eq lsass.exe" wide //weight: 1
        $x_1_4 = {66 00 69 00 6e 00 64 00 [0-8] 6c 00 73 00 61 00 73 00 73 00}  //weight: 1, accuracy: Low
        $x_1_5 = "rundll32.exe" wide //weight: 1
        $x_1_6 = {5c 00 63 00 6f 00 6d 00 73 00 76 00 63 00 73 00 2e 00 64 00 6c 00 6c 00 [0-5] 2b 00 30 00 30 00 30 00 30 00 [0-1] 32 00 34 00}  //weight: 1, accuracy: Low
        $x_1_7 = {5c 00 63 00 6f 00 6d 00 73 00 76 00 63 00 73 00 2e 00 64 00 6c 00 6c 00 [0-255] 32 00 34 00 [0-255] 66 00 75 00 6c 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


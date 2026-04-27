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
        $x_1_4 = " http:\\\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_SuspMsiExec_B_2147965230_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspMsiExec.B"
        threat_id = "2147965230"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMsiExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = " http:\\\\" wide //weight: 1
        $x_1_3 = " https:\\\\" wide //weight: 1
        $x_1_4 = "\\..\\" wide //weight: 1
        $x_1_5 = "\\../" wide //weight: 1
        $x_1_6 = "/..\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_SuspMsiExec_C_2147967684_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspMsiExec.C"
        threat_id = "2147967684"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMsiExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_5_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 [0-4] 50 00}  //weight: 5, accuracy: Low
        $x_2_3 = {20 00 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00}  //weight: 2, accuracy: Low
        $x_2_4 = {20 00 68 00 74 00 74 00 70 00 [0-2] 3a 00 5c 00 5c 00}  //weight: 2, accuracy: Low
        $x_1_5 = {5c 00 2e 00 2e 00 5c 00 [0-32] 2f 00 2e 00 2e 00 [0-2] 2f 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2f 00 2e 00 2e 00 2f 00 [0-32] 2f 00 2e 00 2e 00 [0-2] 2f 00}  //weight: 1, accuracy: Low
        $x_1_7 = {2f 00 2e 00 2e 00 5c 00 [0-32] 2f 00 2e 00 2e 00 [0-2] 2f 00}  //weight: 1, accuracy: Low
        $x_1_8 = {5c 00 2e 00 2e 00 2f 00 [0-32] 5c 00 2e 00 2e 00 [0-2] 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_SuspMsiExec_D_2147967780_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspMsiExec.D"
        threat_id = "2147967780"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMsiExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "/download?id=" wide //weight: 1
        $x_1_3 = "&export=download" wide //weight: 1
        $x_1_4 = "&confirm=t" wide //weight: 1
        $x_1_5 = "&uuid=" wide //weight: 1
        $x_1_6 = " /i " wide //weight: 1
        $x_1_7 = " /qn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


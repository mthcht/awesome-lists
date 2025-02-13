rule HackTool_Win32_Impacketwmiexec_C_2147815696_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Impacketwmiexec.C"
        threat_id = "2147815696"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Impacketwmiexec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_10_2 = "> \\\\127.0.0.1\\C$\\Windows\\Temp\\" wide //weight: 10
        $x_1_3 = " /c " wide //weight: 1
        $x_1_4 = " 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Impacketwmiexec_D_2147815697_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Impacketwmiexec.D"
        threat_id = "2147815697"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Impacketwmiexec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = " /Q " wide //weight: 1
        $x_10_4 = {20 00 5c 00 5c 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 5c 00 [0-32] 5c 00 [0-32] 2e 00 62 00 61 00 74 00}  //weight: 10, accuracy: Low
        $n_100_5 = "\\\\127.0.0.1\\" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Win32_Impacketwmiexec_E_2147815698_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Impacketwmiexec.E"
        threat_id = "2147815698"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Impacketwmiexec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_10_3 = {3e 00 20 00 5c 00 5c 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 5c 00 [0-32] 5c 00 [0-32] 2e 00 74 00 6d 00 70 00}  //weight: 10, accuracy: Low
        $x_1_4 = " 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Impacketwmiexec_F_2147815699_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Impacketwmiexec.F"
        threat_id = "2147815699"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Impacketwmiexec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = " /Q " wide //weight: 1
        $x_10_4 = " 1> \\\\127.0.0.1\\ADMIN$\\__" wide //weight: 10
        $x_1_5 = " 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Impacketwmiexec_G_2147815700_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Impacketwmiexec.G"
        threat_id = "2147815700"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Impacketwmiexec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_10_3 = {3e 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-32] 2e 00 74 00 6d 00 70 00}  //weight: 10, accuracy: Low
        $x_1_4 = " 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Impacketwmiexec_RC_2147816120_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Impacketwmiexec.RC"
        threat_id = "2147816120"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Impacketwmiexec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_100_2 = "> \\\\127.0.0.1\\C$\\Windows\\Temp\\" wide //weight: 100
        $x_1_3 = " /c " wide //weight: 1
        $x_1_4 = " 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Impacketwmiexec_RD_2147816121_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Impacketwmiexec.RD"
        threat_id = "2147816121"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Impacketwmiexec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "103"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = " /Q " wide //weight: 1
        $x_100_4 = {20 00 5c 00 5c 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 5c 00 [0-32] 5c 00 [0-32] 2e 00 62 00 61 00 74 00}  //weight: 100, accuracy: Low
        $n_100_5 = "\\\\127.0.0.1\\" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Win32_Impacketwmiexec_RE_2147816122_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Impacketwmiexec.RE"
        threat_id = "2147816122"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Impacketwmiexec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "103"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_100_3 = {3e 00 20 00 5c 00 5c 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 5c 00 [0-32] 5c 00 [0-32] 2e 00 74 00 6d 00 70 00}  //weight: 100, accuracy: Low
        $x_1_4 = " 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Impacketwmiexec_RF_2147816123_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Impacketwmiexec.RF"
        threat_id = "2147816123"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Impacketwmiexec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "104"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = " /Q " wide //weight: 1
        $x_100_4 = " 1> \\\\127.0.0.1\\ADMIN$\\__" wide //weight: 100
        $x_1_5 = " 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Impacketwmiexec_RG_2147816124_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Impacketwmiexec.RG"
        threat_id = "2147816124"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Impacketwmiexec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "103"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_100_3 = {3e 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-32] 2e 00 74 00 6d 00 70 00}  //weight: 100, accuracy: Low
        $x_1_4 = " 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


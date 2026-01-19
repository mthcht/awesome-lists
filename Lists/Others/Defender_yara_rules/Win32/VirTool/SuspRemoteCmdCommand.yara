rule VirTool_Win32_SuspRemoteCmdCommand_A_2147767977_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRemoteCmdCommand.A"
        threat_id = "2147767977"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRemoteCmdCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "> \\\\127.0.0.1\\C$\\Windows\\Temp\\" wide //weight: 1
        $x_1_3 = " /c " wide //weight: 1
        $x_1_4 = " 2>&1" wide //weight: 1
        $n_10_5 = "\\helios" wide //weight: -10
        $n_10_6 = "\\psscript_" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule VirTool_Win32_SuspRemoteCmdCommand_B_2147767978_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRemoteCmdCommand.B"
        threat_id = "2147767978"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRemoteCmdCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = " /Q " wide //weight: 1
        $x_1_4 = {20 00 5c 00 5c 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 5c 00 [0-32] 5c 00 [0-32] 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: Low
        $n_100_5 = "\\\\127.0.0.1\\" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule VirTool_Win32_SuspRemoteCmdCommand_C_2147767979_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRemoteCmdCommand.C"
        threat_id = "2147767979"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRemoteCmdCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = {3e 00 20 00 5c 00 5c 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 5c 00 [0-32] 5c 00 [0-32] 2e 00 74 00 6d 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = " 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspRemoteCmdCommand_E_2147768071_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRemoteCmdCommand.E"
        threat_id = "2147768071"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRemoteCmdCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = {3e 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-32] 2e 00 74 00 6d 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = " 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspRemoteCmdCommand_F_2147842347_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRemoteCmdCommand.F"
        threat_id = "2147842347"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRemoteCmdCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = " /c echo " wide //weight: 2
        $x_2_3 = " ^> " wide //weight: 2
        $x_2_4 = {20 00 3e 00 20 00 [0-8] 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 [0-32] 2e 00 62 00 61 00 74 00}  //weight: 2, accuracy: Low
        $x_1_5 = " & del " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspRemoteCmdCommand_G_2147849137_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRemoteCmdCommand.G"
        threat_id = "2147849137"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRemoteCmdCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " 1> \\\\localhost\\ADMIN$\\Temp\\{" wide //weight: 1
        $x_1_3 = "} 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspRemoteCmdCommand_H_2147851517_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRemoteCmdCommand.H"
        threat_id = "2147851517"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRemoteCmdCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = "1> \\Windows\\Temp\\" wide //weight: 1
        $x_1_4 = " 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspRemoteCmdCommand_I_2147851518_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRemoteCmdCommand.I"
        threat_id = "2147851518"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRemoteCmdCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = " /c echo " wide //weight: 2
        $x_2_3 = " ^> " wide //weight: 2
        $x_2_4 = {20 00 3e 00 20 00 [0-8] 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 [0-32] 2e 00 62 00 61 00 74 00}  //weight: 2, accuracy: Low
        $x_1_5 = " del " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspRemoteCmdCommand_J_2147922310_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRemoteCmdCommand.J"
        threat_id = "2147922310"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRemoteCmdCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "/Q /c" wide //weight: 1
        $x_1_3 = "1> C:\\windows\\temp" wide //weight: 1
        $x_1_4 = "2>&1 && certutil -encodehex -f" wide //weight: 1
        $x_1_5 = "do reg add HKLM\\" wide //weight: 1
        $x_1_6 = "&& del" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspRemoteCmdCommand_K_2147922311_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRemoteCmdCommand.K"
        threat_id = "2147922311"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRemoteCmdCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "/C" wide //weight: 1
        $x_1_3 = {3e 00 20 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 [0-31] 32 00 3e 00 26 00 31 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspRemoteCmdCommand_N_2147961308_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRemoteCmdCommand.N"
        threat_id = "2147961308"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRemoteCmdCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /Q /c " wide //weight: 1
        $x_1_3 = "> C:\\windows\\temp\\" wide //weight: 1
        $x_1_4 = " 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win32_DumpHive_A_2147762071_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DumpHive.A"
        threat_id = "2147762071"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpHive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00 [0-32] 20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 61 00 6d 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00 [0-32] 20 00 73 00 61 00 76 00 65 00 20 00 48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 73 00 61 00 6d 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_DumpHive_A_2147762071_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DumpHive.A"
        threat_id = "2147762071"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpHive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00 [0-32] 20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00 [0-32] 20 00 73 00 61 00 76 00 65 00 20 00 48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_DumpHive_A_2147762071_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DumpHive.A"
        threat_id = "2147762071"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpHive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00 [0-32] 20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00 [0-32] 20 00 73 00 61 00 76 00 65 00 20 00 48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_DumpHive_B_2147789381_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DumpHive.B"
        threat_id = "2147789381"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpHive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " save hklm\\sam " wide //weight: 1
        $x_1_2 = " save HKEY_LOCAL_MACHINE\\sam " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_DumpHive_B_2147789381_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DumpHive.B"
        threat_id = "2147789381"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpHive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " save hklm\\system " wide //weight: 1
        $x_1_2 = " save HKEY_LOCAL_MACHINE\\system " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_DumpHive_B_2147789381_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DumpHive.B"
        threat_id = "2147789381"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpHive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " save hklm\\security " wide //weight: 1
        $x_1_2 = " save HKEY_LOCAL_MACHINE\\security " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_DumpHive_C_2147796985_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DumpHive.C"
        threat_id = "2147796985"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpHive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 4, accuracy: High
        $x_1_2 = {20 00 73 00 61 00 76 00 65 00 20 00 5c 00 5c 00 [0-48] 5c 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 61 00 6d 00 20 00}  //weight: 1, accuracy: Low
        $x_1_3 = {20 00 73 00 61 00 76 00 65 00 20 00 5c 00 5c 00 [0-48] 5c 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00}  //weight: 1, accuracy: Low
        $x_1_4 = {20 00 73 00 61 00 76 00 65 00 20 00 5c 00 5c 00 [0-48] 5c 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DumpHive_D_2147805714_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DumpHive.D"
        threat_id = "2147805714"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpHive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 4, accuracy: High
        $x_1_2 = " save hklm\\sam \\\\" wide //weight: 1
        $x_1_3 = " save HKEY_LOCAL_MACHINE\\sam \\\\" wide //weight: 1
        $x_1_4 = " save hklm\\system \\\\" wide //weight: 1
        $x_1_5 = " save HKEY_LOCAL_MACHINE\\system \\\\" wide //weight: 1
        $x_1_6 = " save hklm\\security \\\\" wide //weight: 1
        $x_1_7 = " save HKEY_LOCAL_MACHINE\\security \\\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


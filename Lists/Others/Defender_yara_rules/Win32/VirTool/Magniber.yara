rule VirTool_Win32_Magniber_A_2147837768_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.A"
        threat_id = "2147837768"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 70 00 63 00 61 00 6c 00 75 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "/B " wide //weight: 1
        $x_1_3 = "/E:VBScript.Encode " wide //weight: 1
        $x_1_4 = "../../Users/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Magniber_A_2147837768_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.A"
        threat_id = "2147837768"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "/B " wide //weight: 1
        $x_1_3 = "/E:VBScript.Encode " wide //weight: 1
        $x_1_4 = "../../Users/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Magniber_A_2147837768_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.A"
        threat_id = "2147837768"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "/B " wide //weight: 1
        $x_1_3 = "/E:VBScript.Encode " wide //weight: 1
        $x_1_4 = "../../Users/Public/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Magniber_C_2147842714_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.C"
        threat_id = "2147842714"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wscript" wide //weight: 1
        $x_1_2 = "/E:VBScript.Encode" wide //weight: 1
        $x_1_3 = "../../Users/" wide //weight: 1
        $x_1_4 = "/B " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Magniber_D_2147844870_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.D"
        threat_id = "2147844870"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wscript" wide //weight: 1
        $x_1_2 = "/E:VBScript.Encode" wide //weight: 1
        $x_1_3 = "../../Users/" wide //weight: 1
        $x_1_4 = "/B " wide //weight: 1
        $n_10_5 = {2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 75 00 73 00 65 00 72 00 73 00 2f 00 [0-255] 2e 00 76 00 62 00 73 00}  //weight: -10, accuracy: Low
        $n_10_6 = {2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 75 00 73 00 65 00 72 00 73 00 2f 00 [0-255] 2e 00 76 00 62 00 65 00}  //weight: -10, accuracy: Low
        $n_10_7 = {2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 75 00 73 00 65 00 72 00 73 00 2f 00 [0-255] 2e 00 6a 00 73 00}  //weight: -10, accuracy: Low
        $n_10_8 = {2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 75 00 73 00 65 00 72 00 73 00 2f 00 [0-255] 2e 00 6a 00 73 00 65 00}  //weight: -10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule VirTool_Win32_Magniber_B_2147846013_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.B"
        threat_id = "2147846013"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = " && " wide //weight: 1
        $x_1_4 = "% | " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Magniber_B_2147846013_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.B"
        threat_id = "2147846013"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = {73 00 65 00 74 00 20 00 [0-8] 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {20 00 26 00 20 00 65 00 63 00 68 00 6f 00 20 00 21 00 [0-8] 3a 00 7e 00 [0-8] 2c 00 [0-8] 21 00 21 00 [0-8] 3a 00 7e 00 [0-8] 2c 00 [0-8] 21 00 21 00}  //weight: 1, accuracy: Low
        $x_1_4 = {20 00 7c 00 20 00 [0-16] 21 00 [0-8] 3a 00 7e 00 [0-8] 2c 00 [0-8] 21 00 21 00 [0-8] 3a 00 7e 00 [0-8] 2c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Magniber_B_2147846013_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.B"
        threat_id = "2147846013"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = {73 00 65 00 74 00 20 00 [0-8] 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {20 00 26 00 26 00 20 00 63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 65 00 63 00 68 00 6f 00 20 00 25 00 [0-8] 3a 00 7e 00 [0-8] 2c 00 [0-8] 25 00 25 00 [0-8] 3a 00 7e 00 [0-8] 2c 00 [0-8] 25 00 25 00 [0-8] 3a 00 7e 00 [0-8] 2c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "% | powershell -" wide //weight: 1
        $x_1_5 = {25 00 20 00 7c 00 20 00 63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 25 00 [0-8] 3a 00 7e 00 [0-8] 2c 00 [0-8] 25 00 25 00 [0-8] 3a 00 7e 00 [0-8] 2c 00 [0-8] 25 00 25 00 [0-8] 3a 00 7e 00 [0-8] 2c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Magniber_B_2147846013_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.B"
        threat_id = "2147846013"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = "=Set-MpPreference -EnableControlledFolderAccess 0 && cmd /c echo %" wide //weight: 1
        $x_1_3 = "=(Get-WmiObject Win32_ShadowCopy).Delete() && cmd /c echo %" wide //weight: 1
        $x_1_4 = "% | powershell -" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Magniber_E_2147849477_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.E"
        threat_id = "2147849477"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = "(Get-WmiObject Win32_ShadowCopy).Delete()" wide //weight: 1
        $x_1_3 = "Set-MpPreference -EnableControlledFolderAccess 0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Magniber_F_2147888192_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.F"
        threat_id = "2147888192"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-8] 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = ".msi /q" wide //weight: 1
        $x_2_3 = {77 00 6d 00 69 00 63 00 [0-8] 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}


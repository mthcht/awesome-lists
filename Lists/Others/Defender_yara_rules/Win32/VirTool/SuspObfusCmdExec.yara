rule VirTool_Win32_SuspObfusCmdExec_A_2147958106_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspObfusCmdExec.A"
        threat_id = "2147958106"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspObfusCmdExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = "=net&&set " wide //weight: 1
        $x_1_4 = "=stat&&set " wide //weight: 1
        $x_1_5 = "&&echo " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspObfusCmdExec_B_2147958107_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspObfusCmdExec.B"
        threat_id = "2147958107"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspObfusCmdExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = "=stat&&set " wide //weight: 1
        $x_1_4 = "=net&&call set " wide //weight: 1
        $x_1_5 = "&&call %" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspObfusCmdExec_C_2147958108_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspObfusCmdExec.C"
        threat_id = "2147958108"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspObfusCmdExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = " /c " wide //weight: 1
        $x_10_3 = "n^Et^s\"T\"a^t " wide //weight: 10
        $x_10_4 = "fI^n\"d\"S^tr " wide //weight: 10
        $x_10_5 = "n^et^sta^t " wide //weight: 10
        $x_10_6 = "fi^nds^tr " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_SuspObfusCmdExec_D_2147958109_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspObfusCmdExec.D"
        threat_id = "2147958109"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspObfusCmdExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = "powershell.exe" wide //weight: 1
        $x_1_4 = " win32_ComputerSystem" wide //weight: 1
        $x_10_5 = "G\"e\"t\"-\"Wmi\"O\"bje\"c\"t" wide //weight: 10
        $x_10_6 = "G\"e\"t\"-\"Wm^i\"O\"bje\"c\"t" wide //weight: 10
        $x_10_7 = " Get-Wm^iObject" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


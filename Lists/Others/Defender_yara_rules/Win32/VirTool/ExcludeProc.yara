rule VirTool_Win32_ExcludeProc_A_2147766901_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ExcludeProc.A"
        threat_id = "2147766901"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ExcludeProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = "Add-MpPreference -ExclusionProcess " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_ExcludeProc_B_2147772096_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ExcludeProc.B"
        threat_id = "2147772096"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ExcludeProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "Add-MpPreference -ExclusionPath $env:temp" wide //weight: 1
        $x_1_3 = "Add-MpPreference -ExclusionPath $env:appdata" wide //weight: 1
        $x_1_4 = "Net.WebClient).DownloadFile('http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_ExcludeProc_C_2147797730_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ExcludeProc.C"
        threat_id = "2147797730"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ExcludeProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_2_2 = "Add-MpPreference -ExclusionExtension @('exe','dll')" wide //weight: 2
        $x_1_3 = "Add-MpPreference -ExclusionPath @(($pwd).path," wide //weight: 1
        $x_1_4 = "Add-MpPreference -ExclusionPath @($env:UserProfile," wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_ExcludeProc_D_2147816073_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ExcludeProc.D"
        threat_id = "2147816073"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ExcludeProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {20 00 2d 00 45 00 6e 00 63 00 [0-32] 20 00 50 00 41 00 41 00 6a 00 41 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_ExcludeProc_D_2147816073_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ExcludeProc.D"
        threat_id = "2147816073"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ExcludeProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4A" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_ExcludeProc_E_2147846527_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ExcludeProc.E"
        threat_id = "2147846527"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ExcludeProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = " -c" wide //weight: 1
        $x_1_5 = "-MpPreference -ExclusionPath " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


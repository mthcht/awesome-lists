rule HackTool_Win32_LsassDump_F_2147786190_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/LsassDump.F"
        threat_id = "2147786190"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LsassDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "rar.exe a " wide //weight: 10
        $x_10_2 = "lsass.dmp" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_LsassDump_H_2147786191_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/LsassDump.H"
        threat_id = "2147786191"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LsassDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "gsecdump" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_LsassDump_I_2147786192_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/LsassDump.I"
        threat_id = "2147786192"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LsassDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "pwdumpx" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_LsassDump_J_2147786193_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/LsassDump.J"
        threat_id = "2147786193"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LsassDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Mimikatz" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_LsassDump_K_2147786194_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/LsassDump.K"
        threat_id = "2147786194"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LsassDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Invoke-NinjaCopy" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_LsassDump_L_2147786195_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/LsassDump.L"
        threat_id = "2147786195"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LsassDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "pypykatz" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_LsassDump_M_2147786196_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/LsassDump.M"
        threat_id = "2147786196"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LsassDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "crackmapexec" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


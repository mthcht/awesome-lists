rule HackTool_Win32_Nawtlang_A_2147773777_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Nawtlang.A!dha"
        threat_id = "2147773777"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Nawtlang"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Kharpedar123!" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Nawtlang_B_2147773778_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Nawtlang.B!dha"
        threat_id = "2147773778"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Nawtlang"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "52.90.144.40" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


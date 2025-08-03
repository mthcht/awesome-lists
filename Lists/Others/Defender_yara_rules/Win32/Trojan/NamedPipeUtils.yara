rule Trojan_Win32_NamedPipeUtils_MK_2147948214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NamedPipeUtils.MK"
        threat_id = "2147948214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NamedPipeUtils"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "installutil.exe" wide //weight: 1
        $x_1_4 = "named_pipe" wide //weight: 1
        $x_1_5 = "& exit" wide //weight: 1
        $n_1_6 = "pg06e39e-7876-4ba3-beee-42bd80ff363x" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_NamedPipeUtils_MK_2147948214_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NamedPipeUtils.MK"
        threat_id = "2147948214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NamedPipeUtils"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "installutil.exe" wide //weight: 1
        $x_1_4 = "named_pipe" wide //weight: 1
        $x_1_5 = "& exit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


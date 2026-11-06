rule Trojan_Win32_StartupScriptCopy_A_2147981693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StartupScriptCopy.A"
        threat_id = "2147981693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StartupScriptCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xcopy" wide //weight: 1
        $x_1_2 = "\\microsoft\\windows\\start menu\\programs\\startup\\" wide //weight: 1
        $x_1_3 = "\\local\\microsoft" wide //weight: 1
        $x_1_4 = ".vbs" wide //weight: 1
        $x_1_5 = "/y" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


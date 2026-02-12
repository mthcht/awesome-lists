rule Trojan_Win32_BigPlum_A_2147962915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BigPlum.A!dha"
        threat_id = "2147962915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BigPlum"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "powershell" wide //weight: 4
        $x_1_2 = "whoami" wide //weight: 1
        $x_1_3 = "netstat" wide //weight: 1
        $x_1_4 = "curl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


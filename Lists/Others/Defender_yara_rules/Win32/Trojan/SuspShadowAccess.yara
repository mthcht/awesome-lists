rule Trojan_Win32_SuspShadowAccess_C_2147797760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspShadowAccess.C"
        threat_id = "2147797760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspShadowAccess"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "win32_shadowcopy" wide //weight: 1
        $n_5_2 = ".create" wide //weight: -5
        $n_5_3 = "thor\\signatures" wide //weight: -5
        $n_5_4 = ".yms-textfilter" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspShadowAccess_B_2147797761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspShadowAccess.B"
        threat_id = "2147797761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspShadowAccess"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "win32_shadowcopy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspShadowAccess_D_2147817277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspShadowAccess.D"
        threat_id = "2147817277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspShadowAccess"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "120"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {6e 00 74 00 64 00 73 00 75 00 74 00 69 00 6c 00 [0-32] 61 00 63 00 20 00 69 00 6e 00 20 00 6e 00 74 00 64 00 73 00}  //weight: 100, accuracy: Low
        $x_100_2 = {64 00 73 00 64 00 62 00 75 00 74 00 69 00 6c 00 [0-32] 61 00 63 00 20 00 69 00 6e 00 20 00 6e 00 74 00 64 00 73 00}  //weight: 100, accuracy: Low
        $x_10_3 = "ifm" wide //weight: 10
        $x_10_4 = "cr fu" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}


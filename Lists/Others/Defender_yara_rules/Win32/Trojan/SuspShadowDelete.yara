rule Trojan_Win32_SuspShadowDelete_A_2147795404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspShadowDelete.A"
        threat_id = "2147795404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspShadowDelete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "wmic shadowcopy" wide //weight: 2
        $x_2_2 = "wmic.exe shadowcopy" wide //weight: 2
        $x_3_3 = "shadowcopy delete" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspShadowDelete_B_2147795405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspShadowDelete.B"
        threat_id = "2147795405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspShadowDelete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "vssadmin.exe delete shadows" wide //weight: 2
        $x_2_2 = "vssadmin delete shadows" wide //weight: 2
        $x_2_3 = "diskshadow delete shadows" wide //weight: 2
        $x_2_4 = "diskshadow.exe delete shadows" wide //weight: 2
        $x_2_5 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 64 00 65 00 6c 00 65 00 74 00 65 00 [0-16] 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00}  //weight: 2, accuracy: Low
        $n_10_6 = "/oldest" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_SuspShadowDelete_D_2147795447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspShadowDelete.D"
        threat_id = "2147795447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspShadowDelete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {77 00 62 00 61 00 64 00 6d 00 69 00 6e 00 90 00 02 00 30 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 63 00 61 00 74 00 61 00 6c 00 6f 00 67 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspShadowDelete_E_2147797759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspShadowDelete.E"
        threat_id = "2147797759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspShadowDelete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "win32_shadowcopy" wide //weight: 1
        $x_1_2 = "delete" wide //weight: 1
        $n_5_3 = ".create" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspShadowDelete_F_2147797762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspShadowDelete.F"
        threat_id = "2147797762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspShadowDelete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 69 00 6e 00 33 00 32 00 5f 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 [0-240] 64 00 65 00 6c 00 65 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 69 00 6e 00 33 00 32 00 5f 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 [0-240] 72 00 65 00 6d 00 6f 00 76 00 65 00 2d 00}  //weight: 1, accuracy: Low
        $n_5_3 = ".create" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}


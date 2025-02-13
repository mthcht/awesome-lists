rule Trojan_Win32_NtdsExfil_A_2147777152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NtdsExfil.A"
        threat_id = "2147777152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NtdsExfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 76 00 6f 00 6c 00 75 00 6d 00 65 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 [0-48] 5c 00 6e 00 74 00 64 00 73 00 5c 00 6e 00 74 00 64 00 73 00 2e 00 64 00 69 00 74 00}  //weight: 3, accuracy: Low
        $x_3_2 = {5c 00 65 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00 20 00 73 00 65 00 72 00 76 00 65 00 72 00 5c 00 [0-16] 5c 00 63 00 6c 00 69 00 65 00 6e 00 74 00 61 00 63 00 63 00 65 00 73 00 73 00 5c 00 [0-48] 5c 00 6e 00 74 00 64 00 73 00 2e 00 64 00 69 00 74 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_NtdsExfil_B_2147777153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NtdsExfil.B"
        threat_id = "2147777153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NtdsExfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd /c" wide //weight: 1
        $x_1_2 = "cmd.exe /c" wide //weight: 1
        $x_2_3 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 63 00 72 00 65 00 61 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 [0-16] 66 00 6f 00 72 00 3d 00 43 00 3a 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NtdsExfil_C_2147828765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NtdsExfil.C"
        threat_id = "2147828765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NtdsExfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "NtdsAudit.exe" wide //weight: 10
        $x_10_2 = "ntdsutil.exe" wide //weight: 10
        $x_100_3 = "--dump-reversible" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NtdsExfil_H_2147851771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NtdsExfil.H"
        threat_id = "2147851771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NtdsExfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/C copy" wide //weight: 10
        $x_10_2 = "\\Temp\\" wide //weight: 10
        $x_10_3 = "ntds.dit" wide //weight: 10
        $x_10_4 = "volumeshadowcopy" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


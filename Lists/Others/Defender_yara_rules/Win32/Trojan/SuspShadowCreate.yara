rule Trojan_Win32_SuspShadowCreate_A_2147795318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspShadowCreate.A"
        threat_id = "2147795318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspShadowCreate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "wmic shadowcopy" wide //weight: 2
        $x_2_2 = "wmic.exe shadowcopy" wide //weight: 2
        $x_3_3 = "call create volume=" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspShadowCreate_B_2147795319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspShadowCreate.B"
        threat_id = "2147795319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspShadowCreate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vssadmin.exe create shadow /for=" wide //weight: 2
        $x_2_2 = "vssadmin create shadow /for=" wide //weight: 2
        $x_2_3 = "diskshadow create" wide //weight: 2
        $x_2_4 = "diskshadow.exe create" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_SuspShadowCreate_C_2147813366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspShadowCreate.C"
        threat_id = "2147813366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspShadowCreate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {67 00 77 00 6d 00 69 00 [0-48] 77 00 69 00 6e 00 33 00 32 00 5f 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 [0-48] 63 00 72 00 65 00 61 00 74 00 65 00}  //weight: 2, accuracy: Low
        $x_2_2 = {2d 00 77 00 6d 00 69 00 [0-48] 77 00 69 00 6e 00 33 00 32 00 5f 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 [0-48] 63 00 72 00 65 00 61 00 74 00 65 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


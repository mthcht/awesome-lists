rule Trojan_Win32_Evasion_SearchHijack_2147950574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Evasion.SearchHijack.Igfxtray.B"
        threat_id = "2147950574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Evasion"
        severity = "Critical"
        info = "Igfxtray: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\sb_" wide //weight: 1
        $x_1_2 = "igfxtray.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Evasion_EmbeddedPE_2147955109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Evasion.EmbeddedPE.B"
        threat_id = "2147955109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Evasion"
        severity = "Critical"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "bdata_payload.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


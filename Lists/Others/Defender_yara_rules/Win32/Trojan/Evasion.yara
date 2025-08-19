rule Trojan_Win32_Evasion_SearchHijack_2147949579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Evasion.SearchHijack.Igfxtray.AV.B"
        threat_id = "2147949579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Evasion"
        severity = "Critical"
        info = "Igfxtray: an internal category used to refer to some threats"
        info = "AV: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "appdata\\local\\temp\\sb" wide //weight: 1
        $x_1_2 = "igfxtray.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


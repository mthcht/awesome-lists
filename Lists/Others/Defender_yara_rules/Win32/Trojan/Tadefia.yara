rule Trojan_Win32_Tadefia_A_2147710181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tadefia.A!bit"
        threat_id = "2147710181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tadefia"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d3 e0 8b cf f7 d9 8b ?? ?? d3 ?? 0b c2 89 ?? ?? 8b ?? ?? 33}  //weight: 5, accuracy: Low
        $x_5_2 = "This file created by trial version of Quick Batch File Compiler" ascii //weight: 5
        $x_1_3 = {66 6f 72 6d 61 74 20 ?? 3a}  //weight: 1, accuracy: Low
        $x_1_4 = "rd /s /q c:\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


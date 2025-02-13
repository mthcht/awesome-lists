rule HackTool_Win32_CtfExtool_A_2147741908_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CtfExtool.A!!CtfExtool.gen!A"
        threat_id = "2147741908"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CtfExtool"
        severity = "High"
        info = "CtfExtool: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "C:\\Users\\Tavis Ormandy\\Documents\\Projects\\ctftool\\payload64.pdb" ascii //weight: 2
        $x_2_2 = "C:\\Users\\Tavis Ormandy\\Documents\\Projects\\ctftool\\payload32.pdb" ascii //weight: 2
        $x_1_3 = {4d e7 c6 71 28 0f d8 11 a8 2a 00 06 5b 84 43 5c e0 01 00 00 01 00 00 ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 38 00 00 00 80 01 00 00 00 00 00 00 00 00 00 00 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 08 90 22 11 fb 7f 00 00 41 41 41 41 41}  //weight: 1, accuracy: Low
        $x_1_4 = {f7 8e 22 11 fb 7f 00 00 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}


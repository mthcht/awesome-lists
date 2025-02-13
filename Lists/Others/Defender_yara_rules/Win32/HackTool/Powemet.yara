rule HackTool_Win32_Powemet_F_2147730013_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Powemet.F!attk"
        threat_id = "2147730013"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "High"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "AEEAbQBzAGkAVQB0AGkAbAB" wide //weight: 3
        $x_1_2 = "powershell.exe" wide //weight: 1
        $x_1_3 = "hidden" wide //weight: 1
        $x_1_4 = "-encoded" wide //weight: 1
        $x_2_5 = "encodedcommand WwBSAGUAZgBdAC4" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


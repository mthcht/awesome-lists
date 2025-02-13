rule HackTool_Win32_Bombim_B_2147710302_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Bombim.B!bit"
        threat_id = "2147710302"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bombim"
        severity = "High"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d7 d4 b6 af ba e4 d5 a8}  //weight: 1, accuracy: High
        $x_1_2 = {c8 ab d7 d4 b6 af 51 51 cf fb cf a2 ba e4 d5 a8 bb fa 56 31 2e 31 00}  //weight: 1, accuracy: High
        $x_1_3 = {ba e4 d5 a8 b5 c4 c4 da c8 dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

